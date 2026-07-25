package app

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/report"
	"github.com/balyakin/crawlledger/internal/version"
)

func TestSyntheticFormatsAndCanonicalHandoff(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata")
	service := New(bytes.NewReader(nil), nil, version.Info{Version: "test"})
	cases := []struct {
		name   string
		path   string
		format parser.Format
		count  int64
		config string
	}{
		{"combined", "logs/nginx-combined/valid.log", parser.FormatNginxCombined, 3, ""},
		{"nginx-json", "logs/nginx-json/valid.jsonl", parser.FormatNginxJSON, 2, "configs/nonzero-cost.json"},
		{"caddy-json", "logs/caddy-json/valid.jsonl", parser.FormatCaddyJSON, 2, ""},
	}
	var combined report.Model
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			result, err := service.Analyze(context.Background(), AnalyzeRequest{
				Inputs: []string{filepath.Join(fixtures, test.path)}, Format: test.format,
				OutputDir:  filepath.Join(t.TempDir(), "audit"),
				ConfigPath: pathOrEmpty(fixtures, test.config),
			})
			if err != nil {
				t.Fatal(err)
			}
			model := readReport(t, result.ReportJSON)
			if model.Totals.Accepted != test.count || model.Classes == nil || model.Crawlers == nil ||
				model.Routes == nil || model.Findings == nil || model.Warnings == nil {
				t.Fatalf("invalid report contract: %#v", model)
			}
			var classRequests int64
			for _, class := range model.Classes {
				classRequests += class.Requests
			}
			if classRequests != model.Totals.Requests {
				t.Fatal("class conservation failed")
			}
			if test.name == "nginx-json" &&
				(model.Cost.EgressKopecks == nil || model.Cost.AllocatedHostingKopecks == nil) {
				t.Fatal("configured full-coverage cost is unavailable")
			}
			if test.name == "caddy-json" && !hasFinding(model.Findings, domain.FindingMetrics) {
				t.Fatal("Caddy missing metrics were not disclosed")
			}
			if test.name == "combined" {
				combined = model
				if !hasFinding(model.Findings, domain.FindingProbe) {
					t.Fatal("security probe aggregate finding is missing")
				}
			}
		})
	}

	canonicalResult, err := service.Analyze(context.Background(), AnalyzeRequest{
		Inputs: []string{filepath.Join(fixtures, "logs/canonical/valid.jsonl.gz")},
		Format: parser.FormatCrawlLedgerJSON, OutputDir: filepath.Join(t.TempDir(), "audit"),
	})
	if err != nil {
		t.Fatal(err)
	}
	canonical := readReport(t, canonicalResult.ReportJSON)
	if !reflect.DeepEqual(combined.Classes, canonical.Classes) ||
		!reflect.DeepEqual(combined.Crawlers, canonical.Crawlers) ||
		!reflect.DeepEqual(combined.Routes, canonical.Routes) ||
		!reflect.DeepEqual(combined.Findings, canonical.Findings) {
		t.Fatal("raw and canonical semantic reports differ")
	}
}

func TestDeterministicSanitizeAndRobotsFinding(t *testing.T) {
	fixtures := filepath.Join("..", "..", "testdata")
	root := t.TempDir()
	key := filepath.Join(root, "key")
	if err := os.WriteFile(key, bytes.Repeat([]byte("K"), 32), 0o600); err != nil {
		t.Fatal(err)
	}
	service := New(bytes.NewReader(nil), nil, version.Info{Version: "test"})
	var bundles [][]byte
	for index := range 2 {
		result, err := service.Sanitize(context.Background(), SanitizeRequest{
			Inputs:    []string{filepath.Join(fixtures, "logs/nginx-combined/valid.log")},
			Format:    parser.FormatNginxCombined,
			OutputDir: filepath.Join(root, "evidence-"+string(rune('a'+index))), KeyFilePath: key,
		})
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(result.Bundle)
		if err != nil {
			t.Fatal(err)
		}
		bundles = append(bundles, data)
	}
	if !bytes.Equal(bundles[0], bundles[1]) {
		t.Fatal("sanitized gzip bytes are not deterministic")
	}

	logPath := filepath.Join(root, "robots.log")
	if err := os.WriteFile(logPath, []byte(
		`192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /private/page HTTP/1.1" 200 1 "-" "GPTBot/1.0"`+"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := service.Analyze(context.Background(), AnalyzeRequest{
		Inputs: []string{logPath}, Format: parser.FormatNginxCombined,
		OutputDir:  filepath.Join(root, "robots-audit"),
		RobotsPath: filepath.Join(fixtures, "robots/deny.txt"),
	})
	if err != nil {
		t.Fatal(err)
	}
	model := readReport(t, result.ReportJSON)
	if !hasFinding(model.Findings, domain.FindingRobots) {
		t.Fatal("claimed robots.txt violation finding is missing")
	}
}

func readReport(t *testing.T, path string) report.Model {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var model report.Model
	if err := json.Unmarshal(data, &model); err != nil {
		t.Fatal(err)
	}
	return model
}

func hasFinding(values []domain.Finding, kind domain.FindingKind) bool {
	for _, value := range values {
		if value.Kind == kind {
			return true
		}
	}
	return false
}

func pathOrEmpty(root, path string) string {
	if path == "" {
		return ""
	}
	return filepath.Join(root, path)
}
