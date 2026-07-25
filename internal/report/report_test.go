package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/version"
)

func TestBuildAndWrite(t *testing.T) {
	data := domain.ReportData{
		Analysis: domain.Analysis{
			ID: "an_0123456789abcdef0123456789abcdef", StartedAtUS: 1,
			InputFormat: "nginx-combined", CatalogVersion: "test",
		},
		Summary: domain.AnalysisSummary{TotalLines: 1, Accepted: 1},
		Classes: []domain.ClassStats{}, Crawlers: []domain.CrawlerStats{},
		Routes: []domain.RouteStats{}, Findings: []domain.Finding{},
		Cost: domain.CostAllocation{Currency: "RUB", Model: "allocation-v1"},
	}
	model, err := NewBuilder(version.Info{Version: "test"}).Build(data)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if _, err := WriteJSON(context.Background(), root, "report.json", model); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteHTML(context.Background(), root, "report.html", model); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(dir + "/report.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"Content-Security-Policy", "<caption>", "claimed", "never applies"} {
		if !strings.Contains(string(html), marker) {
			t.Fatalf("HTML marker missing: %s", marker)
		}
	}
	if strings.Contains(string(html), "<script") {
		t.Fatal("active content found")
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, err := InspectArtifacts(context.Background(), root, "linked"); err == nil {
		t.Fatal("symlink artifact accepted")
	}
}
