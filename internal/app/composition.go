package app

import (
	"io"
	"log/slog"
	"os"

	"github.com/balyakin/crawlledger/internal/logging"
	"github.com/balyakin/crawlledger/internal/version"
)

func NewCLI(stderr io.Writer) *Service {
	return New(os.Stdin, logging.NewJSON(stderr, slog.LevelInfo), version.Current())
}
