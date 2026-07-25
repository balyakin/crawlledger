package classify

import (
	"net/netip"
	"testing"

	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/normalize"
	"github.com/balyakin/crawlledger/internal/parser"
)

func TestPriorityAndProbeFalsePositive(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	classifier := New(catalogValue, nil, normalize.New(normalize.Key{}))
	record := parser.RawRecord{
		TimestampUS: 1, ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET",
		RequestURI: "/wp-admin/", Status: 404, CacheState: domain.CacheUnknown, UserAgent: "GPTBot/1.0",
	}
	event, err := classifier.Classify(record)
	if err != nil {
		t.Fatal(err)
	}
	if event.PrimaryClass != domain.ClassSecurityProbe || event.Claim == nil {
		t.Fatalf("priority/secondary claim lost: %#v", event)
	}
	if matches := MatchProbes("GET", "/wp-admin/", 200); len(matches) != 0 {
		t.Fatalf("successful admin path was marked probe: %v", matches)
	}
}

func TestTraversalProbe(t *testing.T) {
	tests := map[string]bool{
		"/../secret":               true,
		"/%2e%2e/secret":           true,
		"/safe%2f..%2fsecret":      true,
		"/safe%5c..%5csecret":      true,
		"/path%2fsegment%2ehtml":   false,
		"/path/file%2e%2ebackup":   false,
		"/path/almost..%2fnot-dot": false,
	}
	for uri, want := range tests {
		got := len(MatchProbes("GET", uri, 404)) > 0
		if got != want {
			t.Errorf("MatchProbes(%q) traversal = %t, want %t", uri, got, want)
		}
	}
}

func TestMultiTokenUserAgentWarning(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	classifier := New(catalogValue, nil, normalize.New(normalize.Key{}))
	record := parser.RawRecord{
		TimestampUS: 1, ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET",
		RequestURI: "/", Status: 200, CacheState: domain.CacheUnknown,
		UserAgent: "Googlebot GPTBot",
	}
	event, warnings, err := classifier.ClassifyWithWarnings(record)
	if err != nil {
		t.Fatal(err)
	}
	if event.Claim == nil || event.Claim.Name != "Googlebot" ||
		len(warnings) != 1 || warnings[0] != "ambiguous_user_agent_observed" {
		t.Fatalf("unexpected multi-token classification: %#v, %v", event.Claim, warnings)
	}
}

func FuzzProbeMatcher(f *testing.F) {
	f.Add("GET", "/.git/config", 404)
	f.Fuzz(func(t *testing.T, method, uri string, status int) {
		_ = MatchProbes(method, uri, status)
	})
}
