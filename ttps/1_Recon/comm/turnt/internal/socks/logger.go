package socks

import (
	"log"

	"github.com/praetorian-inc/turnt/internal/logger"
)

type SocksLogger struct{}

func NewSocksLogger() *log.Logger {
	return log.New(&SocksLogger{}, "", 0)
}

func (l *SocksLogger) Write(p []byte) (n int, err error) {
	logger.Error(string(p))
	return len(p), nil
}
