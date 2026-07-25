package app

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/balyakin/crawlledger/internal/atomicfile"
)

type createdDirectory struct {
	root   *os.Root
	parent *os.Root
	name   string
	path   string
	keep   bool
}

func createDirectory(path string) (*createdDirectory, error) {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return nil, errors.New("output must name a new directory")
	}
	parentPath, name := filepath.Split(clean)
	if parentPath == "" {
		parentPath = "."
	}
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return nil, errors.New("invalid output directory name")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	if _, err := parent.Lstat(name); err == nil {
		_ = parent.Close()
		return nil, os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		_ = parent.Close()
		return nil, err
	}
	if err := parent.Mkdir(name, 0o700); err != nil {
		_ = parent.Close()
		return nil, err
	}
	root, err := parent.OpenRoot(name)
	if err != nil {
		_ = parent.Remove(name)
		_ = parent.Close()
		return nil, err
	}
	return &createdDirectory{root: root, parent: parent, name: name, path: clean}, nil
}

func (d *createdDirectory) Close() error {
	rootErr := d.root.Close()
	if !d.keep {
		_ = d.parent.Remove(d.name)
	}
	return errors.Join(rootErr, d.parent.Close())
}

func writeNewPath(ctx context.Context, path string, permission os.FileMode, write func(io.Writer) error) ([]string, error) {
	clean := filepath.Clean(path)
	parentPath, name := filepath.Split(clean)
	if parentPath == "" {
		parentPath = "."
	}
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("invalid output file name")
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return atomicfile.WriteNew(ctx, root, name, permission, write)
}

func pathInside(child, parent string) bool {
	childAbsolute, childErr := filepath.Abs(child)
	parentAbsolute, parentErr := filepath.Abs(parent)
	if childErr != nil || parentErr != nil {
		return true
	}
	relative, err := filepath.Rel(parentAbsolute, childAbsolute)
	return err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
