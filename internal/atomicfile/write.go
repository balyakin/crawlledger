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
	temp, file, err := createTemporary(root, permission)
	if err != nil {
		return nil, err
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

func Replace(ctx context.Context, root *os.Root, name string, permission fs.FileMode, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) ||
		permission&^fs.ModePerm != 0 {
		return errors.New("invalid replacement target")
	}
	temp, file, err := createTemporary(root, permission)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = file.Close()
			_ = root.Remove(temp)
		}
	}()
	if err := file.Chmod(permission); err != nil {
		return errors.Join(err, file.Close())
	}
	written, err := file.Write(data)
	if err != nil || written != len(data) {
		return errors.Join(err, io.ErrShortWrite, file.Close())
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := root.Rename(temp, name); err != nil {
		return fmt.Errorf("replace output: %w", err)
	}
	committed = true
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("open replacement directory: %w", err)
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func createTemporary(root *os.Root, permission fs.FileMode) (string, *os.File, error) {
	for range 10 {
		var suffix [16]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, fmt.Errorf("generate temporary name: %w", err)
		}
		temp := ".crawlledger-" + hex.EncodeToString(suffix[:])
		file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, permission)
		if err == nil {
			return temp, file, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return "", nil, fmt.Errorf("create temporary output: %w", err)
		}
	}
	return "", nil, errors.New("temporary output name collisions exceeded")
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
