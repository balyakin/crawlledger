package input

import (
	"bufio"
	"context"
	"errors"
	"io"
)

var ErrLineTooLong = errors.New("line exceeds configured byte limit")

type LineReader struct {
	reader     *bufio.Reader
	maxBytes   int
	lineNumber int64
	buffer     []byte
}

func NewLineReader(reader io.Reader, maxBytes int) *LineReader {
	return &LineReader{
		reader:   bufio.NewReaderSize(reader, min(maxBytes+1, 64<<10)),
		maxBytes: maxBytes,
		buffer:   make([]byte, 0, min(maxBytes, 64<<10)),
	}
}

func (r *LineReader) Next(ctx context.Context) ([]byte, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, r.lineNumber, err
	}
	r.lineNumber++
	r.buffer = r.buffer[:0]
	tooLong := false
	for {
		fragment, err := r.reader.ReadSlice('\n')
		if !tooLong {
			remaining := r.maxBytes + 2 - len(r.buffer)
			if remaining > 0 {
				take := min(len(fragment), remaining)
				r.buffer = append(r.buffer, fragment[:take]...)
				tooLong = take < len(fragment)
			} else if len(fragment) > 0 {
				tooLong = true
			}
		}
		switch {
		case errors.Is(err, bufio.ErrBufferFull):
			if contextErr := ctx.Err(); contextErr != nil {
				return nil, r.lineNumber, contextErr
			}
			continue
		case err != nil && !errors.Is(err, io.EOF):
			return nil, r.lineNumber, err
		case len(fragment) == 0 && errors.Is(err, io.EOF) && len(r.buffer) == 0:
			r.lineNumber--
			return nil, r.lineNumber, io.EOF
		}
		if n := len(r.buffer); n > 0 && r.buffer[n-1] == '\n' {
			r.buffer = r.buffer[:n-1]
		}
		if n := len(r.buffer); n > 0 && r.buffer[n-1] == '\r' {
			r.buffer = r.buffer[:n-1]
		}
		if tooLong || len(r.buffer) > r.maxBytes {
			return nil, r.lineNumber, ErrLineTooLong
		}
		return r.buffer, r.lineNumber, nil
	}
}
