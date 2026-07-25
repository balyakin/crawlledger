package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/version"
	"github.com/spf13/cobra"
)

func TestVersionAndHelp(t *testing.T) {
	info := version.Info{Version: "1.0.0", Commit: "abc", BuiltAt: "2026-07-24T12:00:00Z", Go: "go1.26.5"}
	var stdout, stderr bytes.Buffer
	if code := Execute(context.Background(), info, &stdout, &stderr); code != 0 {
		t.Fatalf("help exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "version") || strings.Contains(stdout.String(), "completion") {
		t.Fatalf("unexpected help: %s", stdout.String())
	}

	stdout.Reset()
	command := newRootCommand(info, &stdout, &stderr)
	command.SetArgs([]string{"version"})
	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	var got version.Info
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil || got != info {
		t.Fatalf("unexpected version JSON: %q, %v", stdout.String(), err)
	}
	if !strings.HasSuffix(stdout.String(), "\n") || strings.Count(stdout.String(), "\n") != 1 {
		t.Fatalf("version output must be one line: %q", stdout.String())
	}
}

func TestCancellationAndUsage(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	command := newRootCommand(version.Current(), &stdout, &stderr)
	command.SetArgs([]string{"version"})
	command.SetContext(ctx)
	if code := executeCommand(command, &stderr); code != 130 {
		t.Fatalf("canceled command exit = %d, want 130", code)
	}

	stdout.Reset()
	stderr.Reset()
	command = newRootCommand(version.Current(), &stdout, &stderr)
	command.SetArgs([]string{"unknown"})
	if code := executeCommand(command, &stderr); code != 2 {
		t.Fatalf("unknown command exit = %d, want 2", code)
	}

	stderr.Reset()
	internal := &cobra.Command{
		Use: "internal",
		RunE: func(*cobra.Command, []string) error {
			return apperr.New(apperr.CodeInternal, "test", "internal failure", errors.New("secret detail"))
		},
	}
	if code := executeCommand(internal, &stderr); code != 1 {
		t.Fatalf("internal error exit = %d, want 1", code)
	}
	if strings.Contains(stderr.String(), "secret detail") {
		t.Fatalf("internal detail leaked: %s", stderr.String())
	}
}
