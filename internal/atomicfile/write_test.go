package atomicfile

import (
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestWriteNew(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := WriteNew(context.Background(), root, "result", 0o600, func(writer io.Writer) error {
		_, err := io.WriteString(writer, "complete")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(dir + "/result")
	if err != nil || string(data) != "complete" {
		t.Fatalf("bad result: %q %v", data, err)
	}
	if _, err := WriteNew(context.Background(), root, "result", 0o600, func(writer io.Writer) error {
		_, err := io.WriteString(writer, "overwritten")
		return err
	}); err == nil {
		t.Fatal("existing result overwritten")
	}
	data, _ = os.ReadFile(dir + "/result")
	if string(data) != "complete" {
		t.Fatal("existing result changed")
	}
	if _, err := WriteNew(context.Background(), root, "failed", 0o600, func(io.Writer) error {
		return errors.New("write failure")
	}); err == nil {
		t.Fatal("callback failure ignored")
	}
	if _, err := os.Stat(dir + "/failed"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed final name exists")
	}
}

func TestCancellationBeforeCommitLeavesNoOutput(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	_, err = WriteNew(ctx, root, "result", 0o600, func(writer io.Writer) error {
		if _, err := io.WriteString(writer, "complete"); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not returned: %v", err)
	}
	if _, err := os.Stat(dir + "/result"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("canceled output was committed")
	}
}

func TestPanicCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	func() {
		defer func() { _ = recover() }()
		_, _ = WriteNew(context.Background(), root, "output", 0o600, func(io.Writer) error {
			panic("synthetic")
		})
	}()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("panic left files: %v", entries)
	}
}
