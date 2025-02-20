package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

type respChirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

type apiConfig struct {
	fileserverHits atomic.Int32
	logger         *slog.Logger
	dbQueries      *database.Queries
	platform       string
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) registerUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	type RegisterUser struct {
		Email string `json:"email"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		cfg.logger.Error("Error parsing body", "error", err.Error())
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("wrong request body"))
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
	type RespUser struct {
		ID        uuid.UUID `json:"id"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		Email     string    `json:"email"`
	}
	resp, err := cfg.dbQueries.CreateUser(ctx, sql.NullString{
		String: user.Email,
		Valid:  true,
	})

	if err != nil {
		cfg.logger.Error("Error creating user", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
		return
	}
	respUser := RespUser{
		ID:        resp.ID,
		CreatedAt: resp.CreatedAt,
		UpdatedAt: resp.UpdatedAt,
		Email:     user.Email,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	err = json.NewEncoder(w).Encode(respUser)
	if err != nil {
		cfg.logger.Error("Error encoding response", "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
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
		fmt.Println("Error writing response in /reset")
		return
	}
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
		fmt.Println("Error writing response in metrics")
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
	var chirp Chirp
	body, err := io.ReadAll(r.Body)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Error closing body")
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
	chirpParams.UserID = chirp.UserId

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
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request"))
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

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Println("Error connecting to database")
		return
	}
	dbQueries := database.New(db)
	log, f, err := logging.NewLogger("chirpy.log", slog.LevelDebug)
	defer f.Close()
	apiCfg := apiConfig{
		logger:    log,
		dbQueries: dbQueries,
		platform:  platform,
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
