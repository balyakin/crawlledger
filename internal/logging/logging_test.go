package logging

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactionAndLevels(t *testing.T) {
	var output bytes.Buffer
	logger := NewJSON(&output, slog.LevelDebug)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "test",
		slog.String("ClIeNt_Ip", "192.0.2.1"),
		slog.String("op", "analyze"),
	)
	text := output.String()
	if strings.Contains(text, "192.0.2.1") || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("sensitive value was not redacted: %s", text)
	}
	for _, value := range []string{"debug", "INFO", "warn", "error"} {
		if _, ok := ParseLevel(value); !ok {
			t.Fatalf("valid level rejected: %s", value)
		}
	}
	if _, ok := ParseLevel("trace"); ok {
		t.Fatal("invalid level accepted")
	}
}
