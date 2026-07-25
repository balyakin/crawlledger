package app

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/version"
)

func BenchmarkAnalyzeOneMillion(b *testing.B) {
	root := b.TempDir()
	input := filepath.Join(root, "million.log")
	file, err := os.OpenFile(input, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		b.Fatal(err)
	}
	writer := bufio.NewWriterSize(file, 1<<20)
	line := []byte(
		`192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /synthetic HTTP/1.1" 200 1 "-" "SyntheticAgent/1.0"` + "\n",
	)
	for range 1000000 {
		if _, err := writer.Write(line); err != nil {
			b.Fatal(err)
		}
	}
	if err := writer.Flush(); err != nil {
		b.Fatal(err)
	}
	if err := file.Close(); err != nil {
		b.Fatal(err)
	}
	service := New(bytes.NewReader(nil), nil, version.Info{Version: "benchmark"})
	iteration := 0
	b.ResetTimer()
	for b.Loop() {
		output := filepath.Join(root, "audit-"+strconv.Itoa(iteration))
		iteration++
		if _, err := service.Analyze(context.Background(), AnalyzeRequest{
			Inputs: []string{input}, Format: parser.FormatNginxCombined, OutputDir: output,
		}); err != nil {
			b.Fatal(err)
		}
	}
}
