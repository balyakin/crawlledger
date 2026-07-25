package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/report"
	"github.com/balyakin/crawlledger/internal/version"
)

var updateReportGoldens = flag.Bool("update", false, "update golden reports")

func TestReportGoldens(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")
	result, err := New(bytes.NewReader(nil), nil, version.Info{Version: "dev"}).Analyze(
		context.Background(),
		AnalyzeRequest{
			Inputs: []string{filepath.Join(root, "logs", "nginx-combined", "valid.log")},
			Format: parser.FormatNginxCombined, OutputDir: filepath.Join(t.TempDir(), "audit"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	currentJSON, err := os.ReadFile(result.ReportJSON)
	if err != nil {
		t.Fatal(err)
	}
	currentHTML, err := os.ReadFile(result.ReportHTML)
	if err != nil {
		t.Fatal(err)
	}
	goldenJSONPath := filepath.Join(root, "golden", "report.json")
	goldenHTMLPath := filepath.Join(root, "golden", "report.html")
	if *updateReportGoldens {
		if err := os.WriteFile(goldenJSONPath, currentJSON, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenHTMLPath, currentHTML, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	goldenJSON, err := os.ReadFile(goldenJSONPath)
	if err != nil {
		t.Fatal(err)
	}
	goldenHTML, err := os.ReadFile(goldenHTMLPath)
	if err != nil {
		t.Fatal(err)
	}
	currentModel := decodeReport(t, currentJSON)
	goldenModel := decodeReport(t, goldenJSON)
	if normalizeReport(currentModel) != normalizeReport(goldenModel) {
		t.Fatal("report JSON differs from golden; run go test ./internal/app -update")
	}
	if normalizeReportHTML(currentHTML, currentModel) != normalizeReportHTML(goldenHTML, goldenModel) {
		t.Fatal("report HTML differs from golden; run go test ./internal/app -update")
	}
}

func decodeReport(t *testing.T, data []byte) report.Model {
	t.Helper()
	var value report.Model
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func normalizeReport(value report.Model) string {
	value.Analysis.ID, value.Analysis.StartedAt, value.Analysis.FinishedAt = "", "", ""
	data, _ := json.Marshal(value)
	return string(data)
}

func normalizeReportHTML(data []byte, value report.Model) string {
	return strings.NewReplacer(
		value.Analysis.ID, "{analysis-id}",
		value.Analysis.StartedAt, "{started-at}",
		value.Analysis.FinishedAt, "{finished-at}",
	).Replace(string(data))
}
