package normalize

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

type Key [32]byte

func GenerateKey() (Key, error) {
	var key Key
	_, err := io.ReadFull(rand.Reader, key[:])
	return key, err
}

func KeyID(key Key) string {
	sum := sha256.Sum256(key[:])
	return hex.EncodeToString(sum[:8])
}

func LoadOrCreateKey(path string) (Key, error) {
	if path == "" {
		return GenerateKey()
	}
	parent, name := filepath.Split(filepath.Clean(path))
	if parent == "" {
		parent = "."
	}
	if name == "" || name == "." || name == ".." {
		return Key{}, errors.New("invalid key file name")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return Key{}, fmt.Errorf("open key parent: %w", err)
	}
	defer root.Close()
	info, statErr := root.Lstat(name)
	switch {
	case statErr == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return Key{}, errors.New("key must be a regular non-symlink file")
		}
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return Key{}, errors.New("key permissions must not allow group or other access")
		}
		file, err := root.Open(name)
		if err != nil {
			return Key{}, fmt.Errorf("open key: %w", err)
		}
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			_ = file.Close()
			return Key{}, errors.New("key changed while opening")
		}
		var key Key
		_, readErr := io.ReadFull(file, key[:])
		var extra [1]byte
		n, extraErr := file.Read(extra[:])
		closeErr := file.Close()
		if readErr != nil || n != 0 || !errors.Is(extraErr, io.EOF) || closeErr != nil {
			return Key{}, errors.New("key file must contain exactly 32 bytes")
		}
		return key, nil
	case !errors.Is(statErr, os.ErrNotExist):
		return Key{}, fmt.Errorf("inspect key: %w", statErr)
	}
	key, err := GenerateKey()
	if err != nil {
		return Key{}, fmt.Errorf("generate key: %w", err)
	}
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return Key{}, fmt.Errorf("create key: %w", err)
	}
	written, writeErr := io.Copy(file, bytes.NewReader(key[:]))
	if writeErr == nil && written != int64(len(key)) {
		writeErr = io.ErrShortWrite
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		_ = root.Remove(name)
		return Key{}, fmt.Errorf("write key: %w", err)
	}
	return key, nil
}
