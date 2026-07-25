package robots

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/temoto/robotstxt"
)

const maxRobotsBytes int64 = 2 << 20

type Matcher struct{ data *robotstxt.RobotsData }

func Load(path string) (*Matcher, error) {
	parent, name := filepath.Split(filepath.Clean(path))
	if parent == "" {
		parent = "."
	}
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("invalid robots file name")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, fmt.Errorf("open robots parent: %w", err)
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("inspect robots: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxRobotsBytes {
		return nil, errors.New("robots must be a regular non-symlink file up to 2 MiB")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("open robots: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("robots file changed while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxRobotsBytes+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maxRobotsBytes {
		return nil, errors.New("cannot read robots file")
	}
	parsed, err := robotstxt.FromBytes(data)
	if err != nil {
		return nil, errors.New("invalid robots file")
	}
	return &Matcher{data: parsed}, nil
}

func (m *Matcher) Allowed(claimedAgent, rawRequestURI string) (bool, error) {
	if m == nil {
		return true, nil
	}
	parsed, err := url.ParseRequestURI(rawRequestURI)
	if err != nil {
		return false, errors.New("invalid robots request URI")
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if parsed.RawQuery != "" {
		path += "?" + parsed.RawQuery
	}
	return m.data.FindGroup(claimedAgent).Test(path), nil
}
