package protect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/balyakin/crawlledger/internal/input"
)

const followerReadBytes = 64 << 10
const defaultFollowerPoll = 100 * time.Millisecond
const maximumFollowerRetry = 2 * time.Second

type Follower struct {
	root         *os.Root
	name         string
	file         *os.File
	fileInfo     os.FileInfo
	offset       int64
	maxLineBytes int
	line         []byte
	overlong     bool
	pollInterval time.Duration
}

func OpenFollower(path string, maxLineBytes int) (*Follower, error) {
	if !absoluteCleanPath(path) || maxLineBytes <= 0 {
		return nil, errors.New("invalid follower configuration")
	}
	parent, name := filepath.Split(path)
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	file, info, err := openFollowerFile(root, name)
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		_ = file.Close()
		_ = root.Close()
		return nil, err
	}
	return &Follower{
		root: root, name: name, file: file, fileInfo: info, offset: offset,
		maxLineBytes: maxLineBytes,
		line:         make([]byte, 0, min(maxLineBytes+1, followerReadBytes)),
		pollInterval: defaultFollowerPoll,
	}, nil
}

func (follower *Follower) Follow(ctx context.Context, handler func([]byte, error) error) error {
	if handler == nil {
		return errors.New("follower handler is required")
	}
	defer follower.Close()
	buffer := make([]byte, followerReadBytes)
	retryDelay := follower.pollInterval
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := follower.file.Read(buffer)
		if read > 0 {
			retryDelay = follower.pollInterval
			follower.offset += int64(read)
			if handleErr := follower.consume(ctx, buffer[:read], handler); handleErr != nil {
				return handleErr
			}
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			if waitErr := waitFollower(ctx, retryDelay); waitErr != nil {
				return waitErr
			}
			retryDelay = min(retryDelay*2, maximumFollowerRetry)
			continue
		}
		retryDelay = follower.pollInterval
		changed, inspectErr := follower.inspectEOF()
		if inspectErr != nil {
			return inspectErr
		}
		if changed {
			continue
		}
		if err := waitFollower(ctx, follower.pollInterval); err != nil {
			return err
		}
	}
}

func waitFollower(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (follower *Follower) consume(
	ctx context.Context,
	data []byte,
	handler func([]byte, error) error,
) error {
	for len(data) > 0 {
		newline := bytes.IndexByte(data, '\n')
		segment := data
		complete := newline >= 0
		if complete {
			segment = data[:newline]
			data = data[newline+1:]
		} else {
			data = nil
		}
		follower.appendSegment(segment)
		if !complete {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if follower.overlong {
			if err := handler(nil, input.ErrLineTooLong); err != nil {
				return err
			}
		} else {
			line := follower.line
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			if len(line) > follower.maxLineBytes {
				if err := handler(nil, input.ErrLineTooLong); err != nil {
					return err
				}
			} else if err := handler(line, nil); err != nil {
				return err
			}
		}
		follower.line = follower.line[:0]
		follower.overlong = false
	}
	return nil
}

func (follower *Follower) appendSegment(segment []byte) {
	if follower.overlong {
		return
	}
	remaining := follower.maxLineBytes + 1 - len(follower.line)
	if len(segment) > remaining {
		follower.overlong = true
		follower.line = follower.line[:0]
		return
	}
	follower.line = append(follower.line, segment...)
}

func (follower *Follower) inspectEOF() (bool, error) {
	openedInfo, err := follower.file.Stat()
	if err != nil {
		return false, err
	}
	if openedInfo.Size() < follower.offset {
		if _, err := follower.file.Seek(0, io.SeekStart); err != nil {
			return false, err
		}
		follower.offset = 0
		follower.resetPartial()
		return true, nil
	}
	pathInfo, err := follower.root.Lstat(follower.name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("followed log replacement is unsafe")
	}
	if os.SameFile(pathInfo, openedInfo) {
		follower.fileInfo = openedInfo
		return false, nil
	}
	replacement, replacementInfo, err := openFollowerFile(follower.root, follower.name)
	if err != nil {
		return false, err
	}
	if _, err := replacement.Seek(0, io.SeekStart); err != nil {
		_ = replacement.Close()
		return false, err
	}
	previous := follower.file
	follower.file = replacement
	follower.fileInfo = replacementInfo
	follower.offset = 0
	follower.resetPartial()
	return true, previous.Close()
}

func openFollowerFile(root *os.Root, name string) (*os.File, os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.Join(err, errors.New("log must be a regular non-symlink file"))
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, nil, errors.Join(err, errors.New("log changed while opening"))
	}
	return file, opened, nil
}

func (follower *Follower) resetPartial() {
	follower.line = follower.line[:0]
	follower.overlong = false
}

func (follower *Follower) Close() error {
	if follower == nil {
		return nil
	}
	var fileErr error
	var rootErr error
	if follower.file != nil {
		fileErr = follower.file.Close()
		follower.file = nil
	}
	if follower.root != nil {
		rootErr = follower.root.Close()
		follower.root = nil
	}
	return errors.Join(fileErr, rootErr)
}
