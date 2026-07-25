package input

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/balyakin/crawlledger/internal/config"
)

type Spec struct {
	Ordinal int
	Path    string
}

type Metadata struct {
	Ordinal         int
	Compression     string
	CompressedBytes *int64
}

type Source struct {
	Metadata Metadata
	Reader   io.ReadCloser
	stats    *sourceStats
}

type sourceStats struct {
	compressed   int64
	uncompressed int64
	hash         hash.Hash
}

func (s *Source) CompressedBytes() int64   { return s.stats.compressed }
func (s *Source) UncompressedBytes() int64 { return s.stats.uncompressed }
func (s *Source) SHA256() string           { return hex.EncodeToString(s.stats.hash.Sum(nil)) }

func Open(ctx context.Context, spec Spec, stdin io.Reader, limits config.Limits) (*Source, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var base io.ReadCloser
	var size *int64
	if spec.Path == "-" {
		base = io.NopCloser(stdin)
	} else {
		file, fileSize, err := openRegular(spec.Path)
		if err != nil {
			return nil, err
		}
		base, size = file, &fileSize
	}
	stats := &sourceStats{hash: sha256.New()}
	raw := io.TeeReader(&countingReader{reader: base, count: &stats.compressed}, stats.hash)
	buffered := bufio.NewReader(raw)
	magic, peekErr := buffered.Peek(2)
	isGzip := len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b
	if peekErr != nil && !errors.Is(peekErr, io.EOF) {
		_ = base.Close()
		return nil, fmt.Errorf("inspect source: %w", peekErr)
	}
	var stream io.Reader = buffered
	var gzipReader *gzip.Reader
	compression := "plain"
	if isGzip {
		var err error
		gzipReader, err = gzip.NewReader(buffered)
		if err != nil {
			_ = base.Close()
			return nil, errors.New("invalid gzip source")
		}
		gzipReader.Multistream(true)
		stream = gzipReader
		compression = "gzip"
	}
	limited := &expandedReader{
		reader: stream, stats: stats, gzip: isGzip,
		maxUncompressed: limits.MaxUncompressedBytes, maxRatio: limits.MaxGzipRatio,
	}
	return &Source{
		Metadata: Metadata{Ordinal: spec.Ordinal, Compression: compression, CompressedBytes: size},
		Reader:   &sourceCloser{Reader: limited, gzip: gzipReader, base: base},
		stats:    stats,
	}, nil
}

func openRegular(path string) (*os.File, int64, error) {
	parent, name := filepath.Split(filepath.Clean(path))
	if parent == "" {
		parent = "."
	}
	if name == "" || name == "." || name == ".." {
		return nil, 0, errors.New("invalid input name")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, 0, fmt.Errorf("open input parent: %w", err)
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, 0, fmt.Errorf("inspect input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, errors.New("input must be a regular non-symlink file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, 0, fmt.Errorf("open input: %w", err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, 0, errors.New("input changed while opening")
	}
	return file, opened.Size(), nil
}

type countingReader struct {
	reader io.Reader
	count  *int64
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		if *r.count > math.MaxInt64-int64(n) {
			return n, errors.New("input byte count overflow")
		}
		*r.count += int64(n)
	}
	return n, err
}

type expandedReader struct {
	reader          io.Reader
	stats           *sourceStats
	gzip            bool
	maxUncompressed int64
	maxRatio        int64
}

func (r *expandedReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		if r.stats.uncompressed > math.MaxInt64-int64(n) {
			return n, errors.New("uncompressed byte count overflow")
		}
		r.stats.uncompressed += int64(n)
		if r.stats.uncompressed > r.maxUncompressed {
			return n, errors.New("uncompressed input limit exceeded")
		}
		if r.gzip && r.stats.uncompressed > 1<<20 {
			if r.stats.compressed == 0 ||
				r.stats.compressed <= math.MaxInt64/r.maxRatio &&
					r.stats.uncompressed > r.stats.compressed*r.maxRatio {
				return n, errors.New("gzip expansion ratio exceeded")
			}
		}
	}
	return n, err
}

type sourceCloser struct {
	io.Reader
	gzip *gzip.Reader
	base io.Closer
}

func (c *sourceCloser) Close() error {
	var gzipErr error
	if c.gzip != nil {
		gzipErr = c.gzip.Close()
	}
	return errors.Join(gzipErr, c.base.Close())
}
