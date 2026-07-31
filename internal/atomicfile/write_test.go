package atomicfile

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
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

func TestReplaceAtomicallyReplacesExistingFile(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(directory+"/state.json", []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Replace(context.Background(), root, "state.json", 0o600, []byte("complete\n")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(directory + "/state.json")
	if err != nil || string(data) != "complete\n" {
		t.Fatalf("bad replacement: %q %v", data, err)
	}
	info, err := os.Stat(directory + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("replacement mode = %o", info.Mode().Perm())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("temporary file remains: %v", entries)
	}
}

func TestReplaceFailurePreservesExistingFile(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.WriteFile(directory+"/state.json", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Replace(ctx, root, "state.json", 0o600, []byte("new")); !errors.Is(err, context.Canceled) {
		t.Fatalf("replacement returned %v", err)
	}
	data, err := os.ReadFile(directory + "/state.json")
	if err != nil || string(data) != "old" {
		t.Fatalf("failed replacement changed target: %q %v", data, err)
	}
}
