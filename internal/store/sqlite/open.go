package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

func Open(ctx context.Context, path string) (*sql.DB, error) {
	database, absolute, err := open(ctx, path, false)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("secure sqlite permissions: %w", err)
	}
	var foreignKeys int
	if err := database.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		_ = database.Close()
		return nil, fmt.Errorf("foreign_keys pragma is disabled")
	}
	return database, nil
}

func OpenReadOnly(ctx context.Context, path string) (*sql.DB, error) {
	database, _, err := open(ctx, path, true)
	return database, err
}

func OpenReadOnlyFile(ctx context.Context, file *os.File) (*sql.DB, func() error, error) {
	if file == nil {
		return nil, nil, errors.New("database file is required")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, nil, fmt.Errorf("seek database file: %w", err)
	}
	var path string
	cleanup := func() error { return nil }
	switch runtime.GOOS {
	case "linux":
		path = fmt.Sprintf("/proc/self/fd/%d", file.Fd())
	case "darwin":
		path = fmt.Sprintf("/dev/fd/%d", file.Fd())
	default:
		temp, err := os.CreateTemp("", ".crawlledger-sqlite-*")
		if err != nil {
			return nil, nil, fmt.Errorf("create verified database copy: %w", err)
		}
		path = temp.Name()
		cleanup = func() error { return os.Remove(path) }
		if _, err := io.Copy(temp, &contextReader{ctx: ctx, reader: file}); err != nil {
			return nil, nil, errors.Join(err, temp.Close(), cleanup())
		}
		if err := temp.Sync(); err != nil {
			return nil, nil, errors.Join(err, temp.Close(), cleanup())
		}
		if err := temp.Close(); err != nil {
			return nil, nil, errors.Join(err, cleanup())
		}
	}
	database, err := OpenReadOnly(ctx, path)
	if err != nil {
		return nil, nil, errors.Join(err, cleanup())
	}
	return database, cleanup, nil
}

func open(ctx context.Context, path string, readOnly bool) (*sql.DB, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("resolve database path: %w", err)
	}
	slashPath := filepath.ToSlash(absolute)
	if runtime.GOOS == "windows" && !strings.HasPrefix(slashPath, "/") {
		slashPath = "/" + slashPath
	}
	fileURL := &url.URL{Scheme: "file", Path: slashPath}
	query := fileURL.Query()
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "trusted_schema(OFF)")
	query.Add("_pragma", "cache_size(-32768)")
	if readOnly {
		query.Set("mode", "ro")
		query.Set("immutable", "1")
		query.Add("_pragma", "query_only(1)")
	} else {
		query.Add("_pragma", "journal_mode(WAL)")
		query.Add("_pragma", "synchronous(NORMAL)")
		query.Add("_pragma", "temp_store(FILE)")
	}
	fileURL.RawQuery = query.Encode()
	database, err := sql.Open("sqlite", fileURL.String())
	if err != nil {
		return nil, "", fmt.Errorf("open sqlite: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(0)
	pingContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := database.PingContext(pingContext); err != nil {
		_ = database.Close()
		return nil, "", fmt.Errorf("ping sqlite: %w", err)
	}
	return database, absolute, nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(buffer)
	if err == nil {
		err = r.ctx.Err()
	}
	return read, err
}
