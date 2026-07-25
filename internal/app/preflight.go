package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func preflightCommandPaths(inputs []string, output, key string) error {
	inputInfo := make([]os.FileInfo, 0, len(inputs))
	for _, path := range inputs {
		if path == "-" {
			continue
		}
		info, err := lstatAnchored(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("input must be a regular non-symlink file")
		}
		inputInfo = append(inputInfo, info)
	}
	if key != "" {
		info, err := lstatAnchored(key)
		if err == nil {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("key must be a regular non-symlink file")
			}
			for _, input := range inputInfo {
				if os.SameFile(info, input) {
					return errors.New("input and key must not be the same file")
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	clean := filepath.Clean(output)
	parentPath, name := filepath.Split(clean)
	if parentPath == "" {
		parentPath = "."
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return errors.New("invalid output name")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return err
	}
	defer parent.Close()
	if _, err := parent.Lstat(name); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func lstatAnchored(path string) (os.FileInfo, error) {
	parentPath, name := filepath.Split(filepath.Clean(path))
	if parentPath == "" {
		parentPath = "."
	}
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("invalid file name")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return parent.Lstat(name)
}
