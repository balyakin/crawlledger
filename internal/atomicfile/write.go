package atomicfile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
	"strings"
)

func WriteNew(ctx context.Context, root *os.Root, name string, permission fs.FileMode, write func(io.Writer) error) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return nil, errors.New("invalid output basename")
	}
	var temp string
	var file *os.File
	for range 10 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, fmt.Errorf("generate temporary name: %w", err)
		}
		temp = ".crawlledger-" + hex.EncodeToString(suffix[:])
		var err error
		file, err = root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permission)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create temporary output: %w", err)
		}
	}
	if file == nil {
		return nil, errors.New("temporary output name collisions exceeded")
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = root.Remove(temp)
		}
	}()
	cleanup := func() error {
		if committed {
			return nil
		}
		return root.Remove(temp)
	}
	if err := write(file); err != nil {
		closeErr := file.Close()
		return nil, errors.Join(err, closeErr, cleanup())
	}
	if err := ctx.Err(); err != nil {
		closeErr := file.Close()
		return nil, errors.Join(err, closeErr, cleanup())
	}
	if err := file.Sync(); err != nil {
		closeErr := file.Close()
		return nil, errors.Join(err, closeErr, cleanup())
	}
	if err := file.Close(); err != nil {
		return nil, errors.Join(err, cleanup())
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, cleanup())
	}
	if err := root.Link(temp, name); err != nil {
		return nil, errors.Join(fmt.Errorf("publish output: %w", err), cleanup())
	}
	committed = true
	var warnings []string
	if err := root.Remove(temp); err != nil {
		warnings = append(warnings, "temp_cleanup_failed")
	}
	if runtime.GOOS == "windows" {
		return warnings, nil
	}
	if directory, err := root.Open("."); err == nil {
		if syncErr := directory.Sync(); syncErr != nil {
			warnings = append(warnings, "directory_sync_failed")
		}
		if closeErr := directory.Close(); closeErr != nil && !contains(warnings, "directory_sync_failed") {
			warnings = append(warnings, "directory_sync_failed")
		}
	} else {
		warnings = append(warnings, "directory_sync_failed")
	}
	return warnings, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
