package app

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/balyakin/crawlledger/internal/aggregate"
	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/classify"
	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/cost"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/findings"
	"github.com/balyakin/crawlledger/internal/input"
	"github.com/balyakin/crawlledger/internal/jsonstrict"
	"github.com/balyakin/crawlledger/internal/normalize"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/report"
	"github.com/balyakin/crawlledger/internal/robots"
	sqlitestore "github.com/balyakin/crawlledger/internal/store/sqlite"
)

func (s *Service) Analyze(ctx context.Context, request AnalyzeRequest) (result AnalyzeResult, returnErr error) {
	if err := validateAnalyzeRequest(request); err != nil {
		return result, apperr.New(apperr.CodeUsage, "analyze", err.Error(), err)
	}
	cfg, err := config.Load(request.ConfigPath)
	if err != nil {
		return result, apperr.New(apperr.CodeConfig, "analyze", "invalid configuration", err)
	}
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "analyze", "cannot load embedded catalog", err)
	}
	var robotsMatcher *robots.Matcher
	if request.RobotsPath != "" {
		robotsMatcher, err = robots.Load(request.RobotsPath)
		if err != nil {
			return result, apperr.New(apperr.CodeInput, "analyze", "cannot read robots file", err)
		}
	}
	var key normalize.Key
	keyID := ""
	var canonicalManifest *SanitizedManifest
	if request.Format == parser.FormatCrawlLedgerJSON {
		canonicalManifest, err = loadSanitizedManifest(filepath.Join(filepath.Dir(request.Inputs[0]), "sanitized.manifest.json"))
		if err != nil {
			return result, apperr.New(apperr.CodeInput, "analyze", "invalid sanitized manifest", err)
		}
		if canonicalManifest.CatalogVersion != catalogValue.Version() {
			return result, apperr.New(apperr.CodeInput, "analyze", "sanitized catalog version is unsupported", nil)
		}
		keyID = canonicalManifest.KeyID
	}
	if err := preflightCommandPaths(request.Inputs, request.OutputDir, request.KeyFilePath); err != nil {
		return result, apperr.New(apperr.CodeUsage, "analyze", "invalid input, key or output path", err)
	}
	if request.Format != parser.FormatCrawlLedgerJSON {
		key, err = normalize.LoadOrCreateKey(request.KeyFilePath)
		if err != nil {
			return result, apperr.New(apperr.CodeInput, "analyze", "cannot load HMAC key", err)
		}
		keyID = normalize.KeyID(key)
	}
	output, err := createDirectory(request.OutputDir)
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "analyze", "cannot create output directory", err)
	}
	defer func() {
		if closeErr := output.Close(); returnErr == nil && closeErr != nil {
			returnErr = apperr.New(apperr.CodeOutput, "analyze", "cannot close output directory", closeErr)
		}
	}()
	database, err := sqlitestore.Open(ctx, filepath.Join(output.path, "analysis.sqlite"))
	if err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot open analysis database", err)
	}
	output.keep = true
	store := sqlitestore.New(database)
	if err := sqlitestore.Migrate(ctx, database); err != nil {
		_ = database.Close()
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot initialize analysis database", err)
	}
	analysisID, err := domain.NewAnalysisID()
	if err != nil {
		_ = database.Close()
		return result, apperr.New(apperr.CodeInternal, "analyze", "cannot create analysis identifier", err)
	}
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		_ = database.Close()
		return result, apperr.New(apperr.CodeInternal, "analyze", "cannot encode configuration", err)
	}
	analysis := domain.Analysis{
		ID: analysisID, SchemaVersion: 1, ToolVersion: s.build.Version, Status: "running",
		StartedAtUS: time.Now().UTC().UnixMicro(), InputFormat: string(request.Format),
		CatalogVersion: catalogValue.Version(), KeyID: keyID, ConfigJSON: string(configJSON),
	}
	if err := store.CreateAnalysis(ctx, analysis); err != nil {
		_ = database.Close()
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot start analysis", err)
	}
	completed := false
	defer func() {
		if returnErr != nil && !completed {
			status := "failed"
			if errors.Is(returnErr, context.Canceled) {
				status = "canceled"
			}
			failureContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			_ = store.FailAnalysis(failureContext, string(apperr.CodeOf(returnErr)), apperr.UserMessage(returnErr), status)
			cancel()
		}
		if database != nil {
			if closeErr := database.Close(); returnErr == nil && closeErr != nil {
				returnErr = apperr.New(apperr.CodeStorage, "analyze", "cannot close analysis database", closeErr)
			}
		}
	}()
	aggregator := aggregate.New(cfg, store)
	var classifier *classify.Classifier
	if request.Format != parser.FormatCrawlLedgerJSON {
		classifier = classify.New(catalogValue, robotsMatcher, normalize.New(key))
	}
	var totalLines, rejected, skipped, cumulativeBytes, multipleHeaderValues int64
	parseWarnings := make(map[string]int64)
	var canonicalDigest string
	savedErrors := 0
	for ordinal, path := range request.Inputs {
		sourceLimits := cfg.Limits
		sourceLimits.MaxUncompressedBytes -= cumulativeBytes
		if sourceLimits.MaxUncompressedBytes <= 0 {
			return result, apperr.New(apperr.CodeInput, "analyze", "uncompressed input limit exceeded", nil)
		}
		source, err := input.Open(ctx, input.Spec{Ordinal: ordinal, Path: path}, s.stdin, sourceLimits)
		if err != nil {
			return result, apperr.New(apperr.CodeInput, "analyze", "cannot open input source", err)
		}
		if err := store.CreateSource(ctx, ordinal, source.Metadata.Compression, source.Metadata.CompressedBytes); err != nil {
			_ = source.Reader.Close()
			return result, apperr.New(apperr.CodeStorage, "analyze", "cannot register input source", err)
		}
		sourceTotal, sourceAccepted, sourceRejected, sourceSkipped := int64(0), int64(0), int64(0), int64(0)
		lineReader := input.NewLineReader(source.Reader, cfg.Limits.MaxLineBytes)
		formatParser, _ := parser.New(request.Format)
		for {
			line, number, readErr := lineReader.Next(ctx)
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil && !errors.Is(readErr, input.ErrLineTooLong) {
				_ = source.Reader.Close()
				return result, apperr.New(apperr.CodeInput, "analyze", "cannot read input source", readErr)
			}
			sourceTotal++
			totalLines++
			if errors.Is(readErr, input.ErrLineTooLong) {
				rejected, sourceRejected = rejected+1, sourceRejected+1
				if savedErrors < cfg.Limits.MaxSavedParseErrors {
					if err := store.SaveParseError(ctx, ordinal, number, "line_too_long"); err != nil {
						_ = source.Reader.Close()
						return result, apperr.New(apperr.CodeStorage, "analyze", "cannot save parse error", err)
					}
					savedErrors++
				}
				if parseLimitExceeded(totalLines-skipped, rejected, false) {
					_ = source.Reader.Close()
					return result, apperr.New(apperr.CodeParseThreshold, "analyze", "too many invalid log records", nil)
				}
				continue
			}
			if len(line) == 0 {
				skipped, sourceSkipped = skipped+1, sourceSkipped+1
				continue
			}
			parsed, parseErr := formatParser.Parse(line)
			var event domain.Event
			if parseErr == nil {
				parseErr = parsed.Validate()
			}
			if parseErr == nil &&
				(request.Format == parser.FormatCrawlLedgerJSON && parsed.Canonical == nil ||
					request.Format != parser.FormatCrawlLedgerJSON && parsed.Raw == nil) {
				parseErr = errors.New("parser returned an unexpected record representation")
			}
			if parseErr == nil {
				for _, warning := range parsed.Warnings {
					parseWarnings[warning]++
				}
				if parsed.Raw != nil {
					if parsed.Raw.MultipleHeaderValues {
						multipleHeaderValues++
					}
					var classificationWarnings []string
					event, classificationWarnings, parseErr = classifier.ClassifyWithWarnings(*parsed.Raw)
					if parseErr == nil {
						for _, warning := range classificationWarnings {
							parseWarnings[warning]++
						}
					}
				} else {
					event = *parsed.Canonical
					if event.Claim != nil {
						entry, known := catalogValue.ByName(event.Claim.Name)
						if !known || entry.Category != event.Claim.Category ||
							entry.ProtectedDefault != event.Claim.ProtectedDefault {
							parseErr = errors.New("invalid canonical crawler claim")
						}
					}
				}
			}
			if parseErr != nil {
				rejected, sourceRejected = rejected+1, sourceRejected+1
				if savedErrors < cfg.Limits.MaxSavedParseErrors {
					if err := store.SaveParseError(ctx, ordinal, number, safeParseCode(parseErr)); err != nil {
						_ = source.Reader.Close()
						return result, apperr.New(apperr.CodeStorage, "analyze", "cannot save parse error", err)
					}
					savedErrors++
				}
				if parseLimitExceeded(totalLines-skipped, rejected, false) {
					_ = source.Reader.Close()
					return result, apperr.New(apperr.CodeParseThreshold, "analyze", "too many invalid log records", nil)
				}
				continue
			}
			if err := aggregator.Add(ctx, event); err != nil {
				_ = source.Reader.Close()
				return result, apperr.New(apperr.CodeStorage, "analyze", "cannot aggregate event", err)
			}
			sourceAccepted++
		}
		if err := source.Reader.Close(); err != nil {
			return result, apperr.New(apperr.CodeInput, "analyze", "cannot finish input source", err)
		}
		cumulativeBytes += source.UncompressedBytes()
		if cumulativeBytes > cfg.Limits.MaxUncompressedBytes {
			return result, apperr.New(apperr.CodeInput, "analyze", "uncompressed input limit exceeded", nil)
		}
		if err := store.CompleteSource(
			ctx, ordinal, source.UncompressedBytes(), source.SHA256(),
			sourceTotal, sourceAccepted, sourceRejected, sourceSkipped,
		); err != nil {
			return result, apperr.New(apperr.CodeStorage, "analyze", "cannot finalize input source", err)
		}
		if canonicalManifest != nil {
			canonicalDigest = source.SHA256()
		}
	}
	if parseLimitExceeded(totalLines-skipped, rejected, true) {
		return result, apperr.New(apperr.CodeParseThreshold, "analyze", "too many invalid log records", nil)
	}
	summary, err := aggregator.Finish(ctx)
	if err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot finalize aggregates", err)
	}
	summary.AnalysisID, summary.TotalLines, summary.Rejected, summary.Skipped = analysisID, totalLines, rejected, skipped
	if canonicalManifest != nil {
		digest, decodeErr := hex.DecodeString(canonicalManifest.SHA256)
		actual, actualErr := hex.DecodeString(canonicalDigest)
		if decodeErr != nil || actualErr != nil || subtle.ConstantTimeCompare(digest, actual) != 1 ||
			canonicalManifest.Accepted != summary.Accepted {
			return result, apperr.New(apperr.CodeInput, "analyze", "sanitized bundle digest or count mismatch", nil)
		}
	}
	data, err := store.LoadReportData(ctx)
	if err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot read aggregate report data", err)
	}
	data.Analysis, data.Summary = analysis, summary
	detected, err := findings.Detect(cfg, findings.Input{
		Analysis: summary, Routes: data.Routes, Subjects: data.Subjects, Crawlers: data.Crawlers,
		Robots: data.Robots, Probes: data.Probes,
	})
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "analyze", "cannot calculate findings", err)
	}
	if err := store.SaveFindings(ctx, detected); err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot save findings", err)
	}
	data.Findings = detected
	if multipleHeaderValues > 0 {
		data.Warnings = append(data.Warnings, "multiple_header_values_observed")
	}
	if canonicalManifest != nil {
		data.Warnings = append(data.Warnings, canonicalManifest.Warnings...)
	}
	for warning := range parseWarnings {
		data.Warnings = append(data.Warnings, warning)
	}
	data.Cost = domain.CostAllocation{Currency: "RUB", Model: "allocation-v1"}
	if cfg.Costs.MonthlyHostingKopecks == 0 || cfg.Costs.EgressKopecksPerGiB == 0 {
		data.Warnings = append(data.Warnings, "cost_not_configured")
	}
	if summary.FirstEventUS != nil && summary.LastEventUS != nil {
		data.Cost, err = cost.Calculate(cost.Inputs{
			FirstEventUS: *summary.FirstEventUS, LastEventUS: *summary.LastEventUS,
			BytesSent: summary.BytesSent, UpstreamUS: summary.UpstreamDurationUS,
			UpstreamCoveragePPM:   coverage(summary.UpstreamDurationSamples, summary.Accepted),
			MonthlyHostingKopecks: cfg.Costs.MonthlyHostingKopecks,
			EgressKopecksPerGiB:   cfg.Costs.EgressKopecksPerGiB,
		})
		if err != nil {
			return result, apperr.New(apperr.CodeInternal, "analyze", "cannot calculate allocated cost", err)
		}
	}
	model, err := report.NewBuilder(s.build).Build(data)
	if err != nil {
		return result, apperr.New(apperr.CodeInternal, "analyze", "cannot build report", err)
	}
	if warnings, err := report.WriteJSON(ctx, output.root, "report.json", model); err != nil {
		return result, apperr.New(apperr.CodeOutput, "analyze", "cannot publish JSON report", err)
	} else {
		logWarnings(s.logger, warnings)
	}
	if warnings, err := report.WriteHTML(ctx, output.root, "report.html", model); err != nil {
		return result, apperr.New(apperr.CodeOutput, "analyze", "cannot publish HTML report", err)
	} else {
		logWarnings(s.logger, warnings)
	}
	if err := store.CompleteAnalysis(ctx, summary); err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot complete analysis", err)
	}
	completed = true
	if err := store.Optimize(ctx); err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot optimize analysis database", err)
	}
	if err := store.Checkpoint(ctx); err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot checkpoint analysis database", err)
	}
	if err := database.Close(); err != nil {
		return result, apperr.New(apperr.CodeStorage, "analyze", "cannot close analysis database", err)
	}
	database = nil
	artifacts, err := report.InspectArtifacts(ctx, output.root, "analysis.sqlite", "report.html", "report.json")
	if err != nil {
		return result, apperr.New(apperr.CodeOutput, "analyze", "cannot hash workspace artifacts", err)
	}
	manifest := report.Manifest{
		SchemaVersion: 1, AnalysisID: analysisID, ToolVersion: s.build.Version,
		CatalogVersion: catalogValue.Version(), Status: "completed", Artifacts: artifacts,
		Privacy: report.Privacy{
			RawLinesRetained: false, HMACKeyRetained: false, Anonymous: false,
			ResidualRisks: []string{"stable pseudonyms", "timestamps", "routes", "crawler claims", "referer hosts"},
		},
	}
	if warnings, err := report.WriteManifest(ctx, output.root, manifest); err != nil {
		return result, apperr.New(apperr.CodeOutput, "analyze", "cannot publish workspace manifest", err)
	} else {
		logWarnings(s.logger, warnings)
	}
	result = AnalyzeResult{
		AnalysisID: analysisID, Accepted: summary.Accepted, Rejected: rejected,
		ReportJSON: filepath.Join(output.path, "report.json"),
		ReportHTML: filepath.Join(output.path, "report.html"),
	}
	return result, nil
}

func validateAnalyzeRequest(request AnalyzeRequest) error {
	if len(request.Inputs) < 1 || len(request.Inputs) > 64 || !request.Format.Valid() || request.OutputDir == "" {
		return errors.New("input, format and output are required")
	}
	stdin := 0
	for _, path := range request.Inputs {
		if path == "-" {
			stdin++
		}
	}
	if stdin > 1 {
		return errors.New("stdin may be used once")
	}
	if strings.HasPrefix(request.RobotsPath, "http://") || strings.HasPrefix(request.RobotsPath, "https://") {
		return errors.New("robots must be a local file")
	}
	if request.Format == parser.FormatCrawlLedgerJSON {
		if len(request.Inputs) != 1 || request.RobotsPath != "" || request.KeyFilePath != "" {
			return errors.New("canonical analysis requires one input and forbids robots/key flags")
		}
	}
	return nil
}

func safeParseCode(err error) string {
	var parseErr *parser.Error
	if errors.As(err, &parseErr) {
		return parseErr.Code
	}
	return "invalid_uri"
}

func coverage(samples, total int64) int64 {
	return domain.RatioPPM(samples, total)
}

func logWarnings(logger *slog.Logger, warnings []string) {
	if logger == nil {
		return
	}
	for _, warning := range warnings {
		logger.Warn("artifact committed with warning", "op", "publish", "code", warning)
	}
}

func loadSanitizedManifest(path string) (*SanitizedManifest, error) {
	data, err := readAnchoredFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil, errors.New("sanitized manifest must be an object")
	}
	for _, key := range []string{
		"schema_version", "tool_version", "catalog_version", "key_id", "created_at",
		"format", "compression", "sha256", "accepted", "rejected", "skipped",
		"privacy", "warnings",
	} {
		if value, ok := raw[key]; !ok || jsonIsNull(value) {
			return nil, errors.New("sanitized manifest is missing required fields")
		}
	}
	var privacy map[string]json.RawMessage
	if err := json.Unmarshal(raw["privacy"], &privacy); err != nil || privacy == nil {
		return nil, errors.New("sanitized manifest privacy must be an object")
	}
	for _, key := range []string{
		"client_ip", "query_values", "user_agent", "referer",
		"raw_lines_retained", "anonymous", "residual_risks",
	} {
		if value, ok := privacy[key]; !ok || jsonIsNull(value) {
			return nil, errors.New("sanitized privacy is missing required fields")
		}
	}
	var manifest SanitizedManifest
	if err := jsonstrict.Decode(data, &manifest); err != nil {
		return nil, err
	}
	createdAt, timeErr := time.Parse(time.RFC3339Nano, manifest.CreatedAt)
	_, offset := createdAt.Zone()
	if manifest.SchemaVersion != 1 || manifest.Format != "crawlledger-json" || manifest.Compression != "gzip" ||
		manifest.ToolVersion == "" || manifest.CatalogVersion == "" || timeErr != nil || offset != 0 ||
		len(manifest.KeyID) != 16 || len(manifest.SHA256) != 64 ||
		manifest.KeyID != strings.ToLower(manifest.KeyID) ||
		manifest.SHA256 != strings.ToLower(manifest.SHA256) ||
		manifest.Accepted < 0 || manifest.Rejected < 0 || manifest.Skipped < 0 ||
		manifest.Privacy.ClientIP != "hmac-sha256-truncated-128" ||
		manifest.Privacy.QueryValues != "hmac-only" ||
		manifest.Privacy.UserAgent != "hmac-sha256-and-claim-only" ||
		manifest.Privacy.Referer != "host-only" ||
		manifest.Privacy.RawLinesRetained || manifest.Privacy.Anonymous ||
		manifest.Privacy.ResidualRisks == nil || manifest.Warnings == nil ||
		!sort.StringsAreSorted(manifest.Warnings) {
		return nil, errors.New("invalid sanitized manifest contract")
	}
	if _, err := hex.DecodeString(manifest.KeyID); err != nil {
		return nil, errors.New("invalid sanitized key identifier")
	}
	if _, err := hex.DecodeString(manifest.SHA256); err != nil {
		return nil, errors.New("invalid sanitized digest")
	}
	return &manifest, nil
}

func readAnchoredFile(path string, limit int64) ([]byte, error) {
	parentPath, name := filepath.Split(filepath.Clean(path))
	if parentPath == "" {
		parentPath = "."
	}
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("invalid bounded file name")
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readRootFile(root, name, limit)
}
