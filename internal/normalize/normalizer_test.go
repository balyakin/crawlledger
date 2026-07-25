package normalize

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/parser"
)

func TestNormalizePrivacyAndPath(t *testing.T) {
	var key Key
	copy(key[:], strings.Repeat("k", 32))
	normalizer := New(key)
	record := parser.RawRecord{
		TimestampUS: 1, ClientIP: netip.MustParseAddr("192.0.2.10"), Method: "GET",
		RequestURI: "/users/alice@example.test/archive/2026/42?token=VERY_SECRET_VALUE",
		Status:     200, BytesSent: 12, CacheState: domain.CacheUnknown,
		UserAgent: "UNIQUE_AGENT_SECRET", Referer: "https://ref.example/private/SECRET?q=x",
	}
	event, err := normalizer.Normalize(record, Facts{})
	if err != nil {
		t.Fatal(err)
	}
	serialized := event.ClientKey + event.Route + event.URLFingerprint + event.UAHash + strings.Join(event.QueryKeys, ",") + *event.QueryFingerprint
	for _, secret := range []string{"192.0.2.10", "alice@example.test", "VERY_SECRET_VALUE", "UNIQUE_AGENT_SECRET", "/private/SECRET"} {
		if strings.Contains(serialized, secret) {
			t.Fatalf("secret survived normalization: %s", secret)
		}
	}
	if event.Route != "/users/{email}/archive/{year}/{int}" || event.ActionablePrefix == nil || *event.ActionablePrefix != "/users/" {
		t.Fatalf("unexpected route: %s %#v", event.Route, event.ActionablePrefix)
	}
}

func TestActionableBoundary(t *testing.T) {
	var key Key
	normalizer := New(key)
	for _, uri := range []string{"/a%2Fb", "/a//b", "/a/../b", "/привет"} {
		record := parser.RawRecord{
			TimestampUS: 1, ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET",
			RequestURI: uri, Status: 200, CacheState: domain.CacheUnknown,
		}
		event, err := normalizer.Normalize(record, Facts{})
		if err != nil {
			t.Fatal(err)
		}
		if event.ActionablePrefix != nil {
			t.Fatalf("%s unexpectedly actionable: %s", uri, *event.ActionablePrefix)
		}
	}
}

func TestPathRejectsDisplayControls(t *testing.T) {
	for _, character := range []rune{'\u0085', '\u200b', '\u2028', '\u2029', '\u202e', '\ufeff'} {
		if !containsControl("/archive/" + string(character)) {
			t.Errorf("display control U+%04X accepted", character)
		}
	}
}

func TestRefererIPIsCanonicalized(t *testing.T) {
	tests := map[string]string{
		"https://192.0.2.44/private":             "192.0.2.44",
		"https://[2001:db8::1]:8443/private?q=x": "2001:db8::1",
	}
	for input, want := range tests {
		got := refererHost(input)
		if got == nil || *got != want {
			t.Errorf("refererHost(%q) = %v, want %q", input, got, want)
		}
	}
}

func FuzzNormalizePath(f *testing.F) {
	f.Add("/archive/42")
	f.Fuzz(func(t *testing.T, uri string) {
		if len(uri) > 1<<20 {
			t.Skip()
		}
		var key Key
		n := New(key)
		record := parser.RawRecord{
			TimestampUS: 1, ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET",
			RequestURI: uri, Status: 200, CacheState: domain.CacheUnknown,
		}
		event, err := n.Normalize(record, Facts{})
		if err == nil {
			if err := event.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	})
}

func FuzzNormalizeQuery(f *testing.F) {
	f.Add("/?token=secret")
	f.Fuzz(func(t *testing.T, uri string) {
		if len(uri) > 1<<20 {
			t.Skip()
		}
		var key Key
		n := New(key)
		record := parser.RawRecord{
			TimestampUS: 1, ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET",
			RequestURI: uri, Status: 200, CacheState: domain.CacheUnknown,
		}
		_, _ = n.Normalize(record, Facts{})
	})
}
