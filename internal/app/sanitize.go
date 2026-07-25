package app

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/atomicfile"
	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/classify"
	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/input"
	"github.com/balyakin/crawlledger/internal/normalize"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/robots"
)

func (s *Service) Sanitize(ctx context.Context, request SanitizeRequest) (result SanitizeResult, returnErr error) {
	if len(request.Inputs) < 1 || len(request.Inputs) > 64 || request.OutputDir == "" ||
		!request.Format.Valid() || request.Format == parser.FormatCrawlLedgerJSON {
		return result, apperr.New(apperr.CodeUsage, "sanitize", "raw input, format and output are required", nil)
	}
	stdinCount := 0
	for _, path := range request.Inputs {
		if path == "-" {
			stdinCount++
		}
	}
	if stdinCount > 1 {
		return result, apperr.New(apperr.CodeUsage, "sanitize", "stdin may be used once", nil)
	}
	if strings.HasPrefix(request.RobotsPath, "http://") ||
		strings.HasPrefix(request.RobotsPath, "https://") {
		return result, apperr.New(apperr.CodeUsage, "sanitize", "robots must be a local file", nil)
	}
	if err := preflightCommandPaths(request.Inputs, request.OutputDir, request.KeyFilePath); err != nil {
		return result, apperr.New(apperr.CodeUsage, "sanitize", "invalid input, key or output path", err)
	}
	cfg := config.Default()
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "sanitize", "cannot load embedded catalog", err)
	}
	var robotsMatcher *robots.Matcher
	if request.RobotsPath != "" {
		robotsMatcher, err = robots.Load(request.RobotsPath)
		if err != nil {
			return result, apperr.New(apperr.CodeInput, "sanitize", "cannot read robots file", err)
		}
	}
	key, err := normalize.LoadOrCreateKey(request.KeyFilePath)
	if err != nil {
		return result, apperr.New(apperr.CodeInput, "sanitize", "cannot load HMAC key", err)
	}
	classifier := classify.New(catalogValue, robotsMatcher, normalize.New(key))
	output, err := createDirectory(request.OutputDir)
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "sanitize", "cannot create output directory", err)
	}
	defer func() {
		if closeErr := output.Close(); returnErr == nil && closeErr != nil {
			returnErr = apperr.New(apperr.CodeOutput, "sanitize", "cannot close output directory", closeErr)
		}
	}()
	var accepted, rejected, skipped, totalNonEmpty, cumulativeBytes, multipleHeaderValues int64
	parseWarnings := make(map[string]int64)
	compressedHash := sha256.New()
	warnings, err := writeBundle(ctx, output, func(writer io.Writer) error {
		sink := io.MultiWriter(writer, compressedHash)
		gzipWriter := gzip.NewWriter(sink)
		gzipWriter.Header.Name = ""
		gzipWriter.Header.Comment = ""
		gzipWriter.Header.ModTime = time.Unix(0, 0)
		gzipWriter.Header.OS = 255
		for ordinal, path := range request.Inputs {
			sourceLimits := cfg.Limits
			sourceLimits.MaxUncompressedBytes -= cumulativeBytes
			if sourceLimits.MaxUncompressedBytes <= 0 {
				_ = gzipWriter.Close()
				return apperr.New(apperr.CodeInput, "sanitize", "uncompressed input limit exceeded", nil)
			}
			source, err := input.Open(ctx, input.Spec{Ordinal: ordinal, Path: path}, s.stdin, sourceLimits)
			if err != nil {
				_ = gzipWriter.Close()
				return apperr.New(apperr.CodeInput, "sanitize", "cannot open input source", err)
			}
			lineReader := input.NewLineReader(source.Reader, cfg.Limits.MaxLineBytes)
			formatParser, _ := parser.New(request.Format)
			for {
				line, _, readErr := lineReader.Next(ctx)
				if errors.Is(readErr, io.EOF) {
					break
				}
				if readErr != nil && !errors.Is(readErr, input.ErrLineTooLong) {
					_ = source.Reader.Close()
					_ = gzipWriter.Close()
					return apperr.New(apperr.CodeInput, "sanitize", "cannot read input source", readErr)
				}
				if errors.Is(readErr, input.ErrLineTooLong) {
					rejected++
					totalNonEmpty++
				} else if len(line) == 0 {
					skipped++
					continue
				} else {
					totalNonEmpty++
					parsed, parseErr := formatParser.Parse(line)
					if parseErr == nil {
						parseErr = parsed.Validate()
					}
					if parseErr == nil && parsed.Raw == nil {
						parseErr = errors.New("raw parser returned a canonical record")
					}
					if parseErr == nil {
						for _, warning := range parsed.Warnings {
							parseWarnings[warning]++
						}
						if parsed.Raw.MultipleHeaderValues {
							multipleHeaderValues++
						}
						event, classificationWarnings, classifyErr := classifier.ClassifyWithWarnings(*parsed.Raw)
						parseErr = classifyErr
						if parseErr == nil {
							for _, warning := range classificationWarnings {
								parseWarnings[warning]++
							}
							encoded, marshalErr := parser.MarshalCanonical(event)
							if marshalErr != nil {
								_ = source.Reader.Close()
								_ = gzipWriter.Close()
								return apperr.New(apperr.CodeInternal, "sanitize", "cannot encode canonical event", marshalErr)
							}
							encoded = append(encoded, '\n')
							n, writeErr := gzipWriter.Write(encoded)
							if writeErr != nil || n != len(encoded) {
								_ = source.Reader.Close()
								_ = gzipWriter.Close()
								if writeErr != nil {
									return writeErr
								}
								return io.ErrShortWrite
							}
							accepted++
						}
					}
					if parseErr != nil {
						rejected++
					}
				}
				if parseLimitExceeded(totalNonEmpty, rejected, false) {
					_ = source.Reader.Close()
					_ = gzipWriter.Close()
					return apperr.New(apperr.CodeParseThreshold, "sanitize", "too many invalid log records", nil)
				}
			}
			if err := source.Reader.Close(); err != nil {
				_ = gzipWriter.Close()
				return apperr.New(apperr.CodeInput, "sanitize", "cannot finish input source", err)
			}
			if source.UncompressedBytes() > cfg.Limits.MaxUncompressedBytes-cumulativeBytes {
				_ = gzipWriter.Close()
				return apperr.New(apperr.CodeInput, "sanitize", "uncompressed input limit exceeded", nil)
			}
			cumulativeBytes += source.UncompressedBytes()
		}
		if parseLimitExceeded(totalNonEmpty, rejected, true) {
			_ = gzipWriter.Close()
			return apperr.New(apperr.CodeParseThreshold, "sanitize", "too many invalid log records", nil)
		}
		return gzipWriter.Close()
	})
	if err != nil {
		code := apperr.CodeOutput
		var appError *apperr.Error
		if errors.As(err, &appError) {
			code = appError.Code
		}
		return result, apperr.New(code, "sanitize", "cannot create sanitized bundle", err)
	}
	output.keep = true
	logWarnings(s.logger, warnings)
	manifest := SanitizedManifest{
		SchemaVersion: 1, ToolVersion: s.build.Version, CatalogVersion: catalogValue.Version(),
		KeyID: normalize.KeyID(key), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Format: "crawlledger-json", Compression: "gzip",
		SHA256: hex.EncodeToString(compressedHash.Sum(nil)), Accepted: accepted,
		Rejected: rejected, Skipped: skipped,
		Privacy: SanitizedPrivacy{
			ClientIP: "hmac-sha256-truncated-128", QueryValues: "hmac-only",
			UserAgent: "hmac-sha256-and-claim-only", Referer: "host-only",
			RawLinesRetained: false, Anonymous: false,
			ResidualRisks: []string{"stable pseudonyms", "timestamps", "routes", "crawler claims", "referer hosts"},
		},
		Warnings: append([]string{}, warnings...),
	}
	if multipleHeaderValues > 0 {
		manifest.Warnings = append(manifest.Warnings, "multiple_header_values_observed")
	}
	for warning := range parseWarnings {
		manifest.Warnings = append(manifest.Warnings, warning)
	}
	sort.Strings(manifest.Warnings)
	warnings, err = writeManifest(ctx, output, manifest)
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "sanitize", "cannot publish sanitized manifest", err)
	}
	logWarnings(s.logger, warnings)
	return SanitizeResult{
		Accepted: accepted, Rejected: rejected,
		Bundle:   filepath.Join(output.path, "sanitized.jsonl.gz"),
		Manifest: filepath.Join(output.path, "sanitized.manifest.json"),
	}, nil
}

func writeBundle(ctx context.Context, output *createdDirectory, write func(io.Writer) error) ([]string, error) {
	return atomicWrite(ctx, output, "sanitized.jsonl.gz", write)
}

func writeManifest(ctx context.Context, output *createdDirectory, manifest SanitizedManifest) ([]string, error) {
	return atomicWrite(ctx, output, "sanitized.manifest.json", func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(manifest)
	})
}

func atomicWrite(ctx context.Context, output *createdDirectory, name string, write func(io.Writer) error) ([]string, error) {
	return atomicfile.WriteNew(ctx, output.root, name, 0o600, write)
}
