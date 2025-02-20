package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/Flarenzy/chirpy/internal/database"
	"github.com/Flarenzy/chirpy/internal/logging"
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
)

func validEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

type apiConfig struct {
	fileserverHits atomic.Int32
	logger         *slog.Logger
	dbQueries      *database.Queries
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) reset(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
	_, err := w.Write([]byte("Metric value reset"))
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
	Body string `json:"body"`
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

func validateChirp(w http.ResponseWriter, r *http.Request) {
	var chirp Chirp
	type cleanedChirp struct {
		CleanedBody string `json:"cleaned_body"`
	}
	body, err := io.ReadAll(r.Body)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println("Error closing body")
		}
	}(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}
	err = json.Unmarshal(body, &chirp)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad request, incorrect json"))
	}
	chirp.Body = cleanChirp(chirp.Body)
	if len(chirp.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Chirp is too long"))
		return
	}
	w.WriteHeader(http.StatusOK)
	var resp cleanedChirp
	resp.CleanedBody = chirp.Body
	buf, err := json.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}
	_, err = w.Write(buf)
	if err != nil {
		fmt.Println("Error writing response in /validate_chirp")
	}

}

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}
	dbURL := os.Getenv("DB_URL")
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
	mux.HandleFunc("POST /api/validate_chirp", validateChirp)
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
