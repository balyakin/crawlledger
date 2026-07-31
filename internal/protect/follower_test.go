package protect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/balyakin/crawlledger/internal/input"
)

func TestFollowerStartsAtEOFAndReadsAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFollower(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = time.Millisecond
	if err := appendFile(path, "one\ntwo\n"); err != nil {
		t.Fatal(err)
	}
	lines, lineErrors := collectFollowerEvents(t, follower, 2, 0)
	if !reflect.DeepEqual(lines, []string{"one", "two"}) || len(lineErrors) != 0 {
		t.Fatalf("unexpected follower output: lines=%#v errors=%#v", lines, lineErrors)
	}
}

func TestFollowerDiscardsOverlongLineThroughLF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFollower(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = time.Millisecond
	if err := appendFile(path, "secret-too-long\nok\n"); err != nil {
		t.Fatal(err)
	}
	lines, lineErrors := collectFollowerEvents(t, follower, 1, 1)
	if !reflect.DeepEqual(lines, []string{"ok"}) ||
		len(lineErrors) != 1 || !errors.Is(lineErrors[0], input.ErrLineTooLong) {
		t.Fatalf("overlong line leaked or stream did not recover: lines=%#v errors=%#v", lines, lineErrors)
	}
}

func TestFollowerDrainsRenamedFileBeforeReplacement(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "access.log")
	rotated := filepath.Join(directory, "access.log.1")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFollower(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = time.Millisecond
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := appendFile(rotated, "old-inode\n"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("new-inode\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines, lineErrors := collectFollowerEvents(t, follower, 2, 0)
	if !reflect.DeepEqual(lines, []string{"old-inode", "new-inode"}) || len(lineErrors) != 0 {
		t.Fatalf("rotation handling failed: lines=%#v errors=%#v", lines, lineErrors)
	}
}

func TestFollowerHandlesCopyTruncateWithoutReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFollower(path, 32)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var mutex sync.Mutex
	lines := []string{}
	done := make(chan error, 1)
	go func() {
		done <- follower.Follow(ctx, func(line []byte, lineErr error) error {
			if lineErr != nil {
				return lineErr
			}
			mutex.Lock()
			lines = append(lines, string(line))
			count := len(lines)
			mutex.Unlock()
			if count == 1 {
				if err := os.Truncate(path, 0); err != nil {
					return err
				}
				return appendFile(path, "after\n")
			}
			if count == 2 {
				cancel()
			}
			return nil
		})
	}()
	if err := appendFile(path, "before-copytruncate\n"); err != nil {
		t.Fatal(err)
	}
	err = <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("follower returned %v", err)
	}
	mutex.Lock()
	defer mutex.Unlock()
	if !reflect.DeepEqual(lines, []string{"before-copytruncate", "after"}) {
		t.Fatalf("copytruncate handling failed: %#v", lines)
	}
}

func TestFollowerStopsPromptlyOnCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFollower(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- follower.Follow(ctx, func([]byte, error) error { return nil })
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("follower returned %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("follower ignored cancellation")
	}
}

func TestFollowerRetriesReadErrorsUntilCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "access.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	follower, err := OpenFollower(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	follower.pollInterval = time.Millisecond
	if err := follower.file.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = follower.Follow(ctx, func([]byte, error) error { return nil })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("read error was not retried until cancellation: %v", err)
	}
}

func collectFollowerEvents(t *testing.T, follower *Follower, lineCount, errorCount int) ([]string, []error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lines := []string{}
	lineErrors := []error{}
	err := follower.Follow(ctx, func(line []byte, lineErr error) error {
		if lineErr != nil {
			lineErrors = append(lineErrors, lineErr)
		} else {
			lines = append(lines, string(line))
		}
		if len(lines) == lineCount && len(lineErrors) == errorCount {
			cancel()
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("follower returned %v", err)
	}
	return lines, lineErrors
}

func appendFile(path, value string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.WriteString(value)
	return errors.Join(writeErr, file.Close())
}
