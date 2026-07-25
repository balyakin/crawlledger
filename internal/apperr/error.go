package apperr

import (
	"context"
	"errors"
	"fmt"
)

type Code string

const (
	CodeUsage             Code = "usage"
	CodeConfig            Code = "config"
	CodeInput             Code = "input"
	CodeParseThreshold    Code = "parse_threshold"
	CodeStorage           Code = "storage"
	CodeOutput            Code = "output"
	CodeUnsafePolicy      Code = "unsafe_policy"
	CodeUnsupportedPolicy Code = "unsupported_policy"
	CodeInternal          Code = "internal"
)

type Error struct {
	Code    Code
	Op      string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Op == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

func New(code Code, op, message string, err error) error {
	return &Error{Code: code, Op: op, Message: message, Err: err}
}

func CodeOf(err error) Code {
	if err == nil {
		return ""
	}
	var appError *Error
	if errors.As(err, &appError) {
		return appError.Code
	}
	return CodeInternal
}

func ExitCode(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, context.Canceled):
		return 130
	}
	switch CodeOf(err) {
	case CodeUsage, CodeConfig:
		return 2
	case CodeInput, CodeParseThreshold:
		return 3
	case CodeStorage, CodeOutput:
		return 4
	case CodeUnsafePolicy, CodeUnsupportedPolicy:
		return 5
	default:
		return 1
	}
}

func UserMessage(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "operation canceled"
	}
	var appError *Error
	if errors.As(err, &appError) {
		return appError.Error()
	}
	return "internal error"
}
