package protect

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/balyakin/crawlledger/internal/atomicfile"
)

func ReadState(path string) (State, bool, error) {
	if !absoluteCleanPath(path) {
		return State{}, false, errors.New("invalid state path")
	}
	parent, name := filepath.Split(path)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return State{}, false, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxStateBytes {
		return State{}, false, errors.Join(err, errors.New("state must be a bounded regular non-symlink file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return State{}, false, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return State{}, false, errors.Join(err, errors.New("state changed while opening"))
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > maxStateBytes {
		return State{}, false, errors.Join(readErr, closeErr, errors.New("cannot read bounded state"))
	}
	state, err := DecodeState(data)
	return state, true, err
}

func WriteState(ctx context.Context, path string, state State) error {
	if !absoluteCleanPath(path) {
		return errors.New("invalid state path")
	}
	data, err := EncodeState(state)
	if err != nil {
		return err
	}
	parent, name := filepath.Split(path)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("state target is unsafe")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicfile.Replace(ctx, root, name, 0o600, data)
}
