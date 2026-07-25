package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/balyakin/crawlledger/internal/cli"
	"github.com/balyakin/crawlledger/internal/version"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := cli.Execute(ctx, version.Current(), os.Stdout, os.Stderr)
	stop()
	os.Exit(exitCode)
}
