package logging

import (
	"log/slog"
	"os"
)

type MyHandler struct {
	Level slog.Level
}

func NewLogger(fileName string, level slog.Level) (*slog.Logger, *os.File, error) {
	f, err := os.OpenFile(fileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		slog.Error("Failed to open log file", "file", fileName, "error", err)
		return nil, nil, err
	}
	logger := slog.New(slog.NewJSONHandler(f, &slog.HandlerOptions{Level: level}))
	return logger, f, nil
}
