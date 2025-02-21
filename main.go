package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Flarenzy/chirpy/internal/auth"
	"github.com/Flarenzy/chirpy/internal/database"
	"github.com/Flarenzy/chirpy/internal/logging"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"io"
	"log/slog"
	"net/http"
	"net/mail"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

type RespUser struct {
	Id           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type RegisterUser struct {
	Email            string `json:"email"`
	Password         string `json:"password"`
	ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty"`
}

type respChirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type PolkaWebhook struct {
	Event string `json:"event"`
	Data  struct {
		UserID string `json:"user_id"`
	} `json:"data"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
	logger         *slog.Logger
	dbQueries      *database.Queries
	platform       string
	tokenSecret    string
	polkaApiKey    string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) registerUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		cfg.logger.Error("Error parsing body", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("wrong request body"))
		return
	}
	defer r.Body.Close()
	var user RegisterUser
	err = json.Unmarshal(body, &user)
	if err != nil {
		cfg.logger.Error("Error unmarshaling body", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("wrong request body"))
		return
	}
	if !validEmail(user.Email) || user.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("wrong request body"))
		return
	}

	var createUserParams database.CreateUserParams
	createUserParams.Email = sql.NullString{
		String: user.Email,
		Valid:  true,
	}
	createUserParams.HashedPassword, err = auth.HashPassword(user.Password)
	if err != nil {
		cfg.logger.Error("Error hashing password", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("wrong request body"))
		return
	}
	resp, err := cfg.dbQueries.CreateUser(ctx, createUserParams)

	if err != nil {
		cfg.logger.Error("Error creating user", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	respUser := RespUser{
		Id:          resp.ID,
		CreatedAt:   resp.CreatedAt,
		UpdatedAt:   resp.UpdatedAt,
		Email:       resp.Email.String,
		IsChirpyRed: resp.IsChirpyRed.Bool,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(respUser)
	if err != nil {
		cfg.logger.Error("Error encoding response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
}

func (cfg *apiConfig) reset(w http.ResponseWriter, r *http.Request) {
	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ctx := r.Context()
	err := cfg.dbQueries.DeleteAllUsers(ctx)
	if err != nil {
		cfg.logger.Error("Error deleting all users", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
	_, err = w.Write([]byte("all values reset"))
	if err != nil {
		cfg.logger.Error("Error writing response in /reset")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	cfg.logger.Info("Reset complete")
}

func (cfg *apiConfig) metrics(w http.ResponseWriter, _ *http.Request) {
	htmlTemplate := `
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
`
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	val := cfg.fileserverHits.Load()
	msg := fmt.Sprintf(htmlTemplate, val)
	_, err := w.Write([]byte(msg))
	if err != nil {
		cfg.logger.Error("Error writing response in metrics")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
}

type Chirp struct {
	Body   string    `json:"body"`
	UserId uuid.UUID `json:"user_id"`
}

func cleanChirp(chirp string) string {
	profaneWords := []string{"kerfuffle", "sharbert", "fornax"}
	var newChirpWords []string
	for _, c := range strings.Fields(chirp) {
		var newWord string
		for _, word := range profaneWords {
			if strings.ToLower(c) == word {
				newWord = "****"
				break
			} else {
				newWord = c
			}
		}
		newChirpWords = append(newChirpWords, newWord)
	}
	newChirp := strings.Join(newChirpWords, " ")
	return newChirp

}

func (cfg *apiConfig) createChirp(w http.ResponseWriter, r *http.Request) {
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		cfg.logger.Error("Error getting bearer token", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userID, err := auth.ValidateJWT(bearerToken, cfg.tokenSecret)
	if err != nil {
		cfg.logger.Error("Error validating jwt token", "error", err.Error())
		cfg.logger.Error("The jwt token is", "token", bearerToken)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var chirp Chirp
	body, err := io.ReadAll(r.Body)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			cfg.logger.Error("Error closing body")
		}
	}(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
	}
	err = json.Unmarshal(body, &chirp)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request, incorrect json"))
		return
	}
	if len(chirp.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Chirp is too long"))
		return
	}
	chirp.Body = cleanChirp(chirp.Body)
	var chirpParams database.CreateChirpParams
	chirpParams.Body = chirp.Body
	chirpParams.UserID = userID

	ctx := r.Context()
	createChirp, err := cfg.dbQueries.CreateChirp(ctx, chirpParams)
	if err != nil {
		cfg.logger.Error("Error creating chirp", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	var rChirp respChirp
	rChirp.ID = createChirp.ID
	rChirp.CreatedAt = createChirp.CreatedAt
	rChirp.UpdatedAt = createChirp.UpdatedAt
	rChirp.Body = createChirp.Body
	rChirp.UserID = createChirp.UserID
	buf, err := json.Marshal(rChirp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write(buf)

}

func (cfg *apiConfig) getAllChirp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	chirps, err := cfg.dbQueries.GetAllChirps(ctx)
	var respChirps []respChirp
	for _, chirp := range chirps {
		var rChirp respChirp
		rChirp.ID = chirp.ID
		rChirp.CreatedAt = chirp.CreatedAt
		rChirp.UpdatedAt = chirp.UpdatedAt
		rChirp.Body = chirp.Body
		rChirp.UserID = chirp.UserID
		respChirps = append(respChirps, rChirp)
	}
	if err != nil {
		cfg.logger.Error("Error getting all chirps", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(respChirps)
	if err != nil {
		cfg.logger.Error("Error encoding response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}
}

func (cfg *apiConfig) getChirpById(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	chirpId := r.PathValue("chirp_id")
	chirpUUID, err := uuid.Parse(chirpId)
	if err != nil {
		cfg.logger.Error("Error getting chirp UUID", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
		return
	}
	var rChirp respChirp
	chirp, err := cfg.dbQueries.GetChirpByID(ctx, chirpUUID)
	if err != nil {
		cfg.logger.Error("Error getting chirp from DB", "error", err.Error())
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "not found",
		})
		return
	}
	rChirp.ID = chirp.ID
	rChirp.CreatedAt = chirp.CreatedAt
	rChirp.UpdatedAt = chirp.UpdatedAt
	rChirp.Body = chirp.Body
	rChirp.UserID = chirp.UserID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(rChirp)
	if err != nil {
		cfg.logger.Error("Error encoding response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}
}

func (cfg *apiConfig) loginUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	expiration := time.Hour
	cfg.logger.Debug("Login User", "expiration", expiration)
	var logUser RegisterUser
	body, err := io.ReadAll(r.Body)
	if err != nil {
		cfg.logger.Error("Error reading body", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
		return
	}
	defer r.Body.Close()
	err = json.Unmarshal(body, &logUser)
	if err != nil {
		cfg.logger.Error("Error unmarshalling body in loginUser", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
		return
	}

	usr, err := cfg.dbQueries.GetUserByEmail(ctx, sql.NullString{
		String: logUser.Email,
		Valid:  true,
	})
	if err != nil {
		cfg.logger.Error("Error getting user by email", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Incorrect email or password"))
		return
	}
	if !auth.CheckPasswordHash(logUser.Password, usr.HashedPassword) {
		cfg.logger.Error("Error getting user by email", "error", "Incorrect password")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Incorrect email or password"))
		return
	}
	cfg.logger.Info("Successfully logged in", "email", logUser.Email, "duration", expiration)
	jwt, err := auth.MakeJWT(usr.ID, cfg.tokenSecret, expiration)
	if err != nil {
		cfg.logger.Error("Error creating JWT in login request", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
		return
	}
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		cfg.logger.Error("Error creating refresh token in login request", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
		return
	}
	var createRefreshTokenParams database.CreateRefreshTokenParams
	createRefreshTokenParams.UserID = usr.ID
	createRefreshTokenParams.Token = refreshToken
	_, err = cfg.dbQueries.CreateRefreshToken(ctx, createRefreshTokenParams)
	if err != nil {
		cfg.logger.Error("Error creating refresh token in login request", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
		return
	}
	var respUser RespUser
	respUser.Id = usr.ID
	respUser.CreatedAt = usr.CreatedAt
	respUser.UpdatedAt = usr.UpdatedAt
	respUser.Email = usr.Email.String
	respUser.Token = jwt
	respUser.RefreshToken = refreshToken
	respUser.IsChirpyRed = usr.IsChirpyRed.Bool
	cfg.logger.Info("Logged in user", "user", respUser)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(respUser)
	if err != nil {
		cfg.logger.Error("Error encoding response loginUser", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}

}

func (cfg *apiConfig) refreshAccessToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		cfg.logger.Error("Error getting bearer token", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	usr, err := cfg.dbQueries.GetUserFromRefreshToken(ctx, bearerToken)
	if err != nil {
		cfg.logger.Error("Error getting user from refresh token", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	if usr.RevokedAt.Valid {
		cfg.logger.Error("Token revoked at", "time", usr.RevokedAt.Time)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	if time.Now().UTC().After(usr.ExpiresAt) {
		cfg.logger.Error("Token expired", "error", errors.New("Token expired"), "token", bearerToken)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	jwt, err := auth.MakeJWT(usr.ID, cfg.tokenSecret, time.Hour)
	if err != nil {
		cfg.logger.Error("Error creating JWT in refresh token", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal server error"))
		return
	}
	type returnToken struct {
		Token string `json:"token"`
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(returnToken{
		Token: jwt,
	})
}

func (cfg *apiConfig) revokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		cfg.logger.Error("Error getting bearer token", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	err = cfg.dbQueries.RevokeRefreshToken(ctx, bearerToken)
	if err != nil {
		cfg.logger.Error("Error revoking refresh token", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		cfg.logger.Error("Error getting bearer token in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	userID, err := auth.ValidateJWT(bearerToken, cfg.tokenSecret)
	if err != nil {
		cfg.logger.Error("Error validating bearer token in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	usr, err := cfg.dbQueries.GetUserByID(ctx, userID)
	if err != nil {
		cfg.logger.Error("Error getting user by ID in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
		return
	}
	var newUser RegisterUser
	body, err := io.ReadAll(r.Body)
	if err != nil {
		cfg.logger.Error("Error reading body in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	defer r.Body.Close()
	err = json.Unmarshal(body, &newUser)
	if err != nil {
		cfg.logger.Error("Error unmarshalling body in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
		return
	}
	if newUser.Email == "" || newUser.Password == "" || !validEmail(newUser.Email) {
		cfg.logger.Error("invalid username or password", "error", errors.New("invalid username or password"))
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("invalid username or password"))
		return
	}
	hashedPassword, err := auth.HashPassword(newUser.Password)
	if err != nil {
		cfg.logger.Error("Error hashing password in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	updatedUser, err := cfg.dbQueries.UpdateUserEmailAndPassword(ctx, database.UpdateUserEmailAndPasswordParams{
		Email: sql.NullString{
			String: newUser.Email,
			Valid:  true,
		},
		HashedPassword: hashedPassword,
		ID:             usr.ID,
	})
	if err != nil {
		cfg.logger.Error("Error updating user in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
	var respUser RespUser
	respUser.Id = updatedUser.ID
	respUser.Email = newUser.Email
	respUser.UpdatedAt = updatedUser.UpdatedAt
	respUser.CreatedAt = updatedUser.CreatedAt
	respUser.IsChirpyRed = updatedUser.IsChirpyRed.Bool
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(respUser)
	if err != nil {
		cfg.logger.Error("Error marshalling body in updateUser", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
		return
	}
}

func (cfg *apiConfig) deleteChirp(w http.ResponseWriter, r *http.Request) {
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))
	if err != nil {
		cfg.logger.Error("Error parsing chirp ID in deleteChirp", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "bad request",
		})
		return
	}
	ctx := r.Context()
	bearerToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		cfg.logger.Error("Error getting bearer token in deleteChirp", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "unauthorized",
		})
		return
	}
	usr, err := auth.ValidateJWT(bearerToken, cfg.tokenSecret)
	if err != nil {
		cfg.logger.Error("Error validating bearer token in deleteChirp", "error", err.Error())
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "unauthorized",
		})
		return
	}
	chirp, err := cfg.dbQueries.GetChirpByID(ctx, chirpID)
	if err != nil {
		cfg.logger.Error("Error getting chirp by ID in deleteChirp", "error", err.Error(), "id", chirpID)
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "not found",
		})
		return
	}
	if chirp.UserID != usr {
		cfg.logger.Error("Error unauthorized user trying to delete chirp  in deleteChirp",
			"error", errors.New("unauthorized"), "id", usr, "chirpID", chirp.ID)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "forbidden",
		})
		return
	}
	err = cfg.dbQueries.DeleteChirpById(ctx, chirp.ID)
	if err != nil {
		cfg.logger.Error("Error deleting chirp in deleteChirp", "error", err.Error(), "chirpID", chirp.ID)
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "chirp not found",
		})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (cfg *apiConfig) polkaWebhookUpdateUserToChirpyRed(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var polkaWebhook PolkaWebhook
	body, err := io.ReadAll(r.Body)
	if err != nil {
		cfg.logger.Error("Error reading body in polkaWebhookUpdateUserToChirpyRed", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "bad request",
		})
		return
	}
	defer r.Body.Close()
	err = json.Unmarshal(body, &polkaWebhook)
	if err != nil {
		cfg.logger.Error("Error unmarshalling polkaWebhookUpdateUserToChirpyRed", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "bad request",
		})
		return
	}
	if polkaWebhook.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	userID, err := uuid.Parse(polkaWebhook.Data.UserID)
	if err != nil {
		cfg.logger.Error("Error parsing UUID polkaWebhookUpdateUserToChirpyRed", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "bad request",
		})
		return
	}
	err = cfg.dbQueries.UpdateUserToChirpyRed(ctx, userID)
	if err != nil {
		cfg.logger.Error("Error updating user in polkaWebhookUpdateUserToChirpyRed", "error", err.Error())
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(struct {
			Status string `json:"status"`
		}{
			Status: "not found",
		})
		return
	}
	cfg.logger.Info("Updated user in polkaWebhookUpdateUserToChirpyRed", "user", userID)
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	tokenSecret := os.Getenv("TOKEN_SECRET")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("Error connecting to database")
		return
	}
	dbQueries := database.New(db)
	log, f, err := logging.NewLogger("chirpy.log", slog.LevelDebug)
	defer f.Close()
	apiCfg := apiConfig{
		logger:      log,
		dbQueries:   dbQueries,
		platform:    platform,
		tokenSecret: tokenSecret,
	}
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}
	fileHandler := http.FileServer(http.Dir("."))
	mux.Handle("/app/", http.StripPrefix("/app", apiCfg.middlewareMetricsInc(fileHandler)))
	mux.Handle("GET /api/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			fmt.Println("Error writing response /app")
			return
		}

	}))
	mux.HandleFunc("GET /admin/metrics", apiCfg.metrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.reset)
	mux.HandleFunc("POST /api/chirps", apiCfg.createChirp)
	mux.HandleFunc("POST /api/users", apiCfg.registerUser)
	mux.HandleFunc("GET /api/chirps", apiCfg.getAllChirp)
	mux.HandleFunc("GET /api/chirps/{chirp_id}", apiCfg.getChirpById)
	mux.HandleFunc("POST /api/login", apiCfg.loginUser)
	mux.HandleFunc("POST /api/refresh", apiCfg.refreshAccessToken)
	mux.HandleFunc("POST /api/revoke", apiCfg.revokeRefreshToken)
	mux.HandleFunc("PUT /api/users", apiCfg.updateUser)
	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirp)
	mux.HandleFunc("POST /api/polka/webhooks", apiCfg.polkaWebhookUpdateUserToChirpyRed)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		os.Exit(0)
	}()
	fmt.Println("Listening on", server.Addr)
	err = server.ListenAndServe()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer func(server *http.Server, ctx context.Context) {
		err := server.Shutdown(ctx)
		if err != nil {
			fmt.Println(err)
		}
	}(server, context.Background())
}
