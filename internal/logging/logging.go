package logging

import (
	"io"
	"log/slog"
	"strings"
)

func NewJSON(writer io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(writer, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if isSensitiveKey(attr.Key) {
				return slog.String(attr.Key, "[REDACTED]")
			}
			return attr
		},
	}))
}

func isSensitiveKey(key string) bool {
	switch strings.ToLower(key) {
	case "authorization", "client_ip", "cookie", "hmac_key", "query", "raw_line",
		"referer", "request_uri", "user_agent":
		return true
	default:
		return false
	}
}

func ParseLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(value) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return slog.LevelInfo, false
	}
}
