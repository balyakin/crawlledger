package input

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/balyakin/crawlledger/internal/config"
)

func TestLineReader(t *testing.T) {
	reader := NewLineReader(bytes.NewBufferString("one\r\ntwo"), 4)
	line, number, err := reader.Next(context.Background())
	if err != nil || string(line) != "one" || number != 1 {
		t.Fatalf("first line: %q %d %v", line, number, err)
	}
	line, number, err = reader.Next(context.Background())
	if err != nil || string(line) != "two" || number != 2 {
		t.Fatalf("last line: %q %d %v", line, number, err)
	}
	if _, _, err := reader.Next(context.Background()); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}

	reader = NewLineReader(bytes.NewBufferString("secret-too-long\nok\n"), 4)
	if line, _, err := reader.Next(context.Background()); !errors.Is(err, ErrLineTooLong) || line != nil {
		t.Fatalf("long line leaked: %q %v", line, err)
	}
	line, _, err = reader.Next(context.Background())
	if err != nil || string(line) != "ok" {
		t.Fatalf("drain failed: %q %v", line, err)
	}
	reader = NewLineReader(bytes.NewBufferString("four\r\n"), 4)
	line, _, err = reader.Next(context.Background())
	if err != nil || string(line) != "four" {
		t.Fatalf("CRLF at exact limit rejected: %q %v", line, err)
	}
}

func TestPlainAndGzip(t *testing.T) {
	dir := t.TempDir()
	plain := filepath.Join(dir, "input")
	if err := os.WriteFile(plain, []byte("a\nb\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "compressed")
	file, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(file)
	if _, err := gz.Write([]byte("a\nb\n")); err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(gz.Close(), file.Close()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{plain, gzPath} {
		source, err := Open(context.Background(), Spec{Path: path}, bytes.NewReader(nil), config.Default().Limits)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(source.Reader)
		if err != nil || string(data) != "a\nb\n" {
			t.Fatalf("%s: %q %v", path, data, err)
		}
		if err := source.Reader.Close(); err != nil {
			t.Fatal(err)
		}
		if source.SHA256() == "" {
			t.Fatal("missing source digest")
		}
	}
}
