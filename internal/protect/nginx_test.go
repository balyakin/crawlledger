package protect

import (
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
)

func TestNginxNamesAndOpaqueKeyVectors(t *testing.T) {
	config := nginxTestConfig()
	names := NginxNamesFor(config)
	if names.Suffix != "193511d5" ||
		names.EmergencyVariable != "crawlledger_example_193511d5_emergency_key" ||
		names.EmergencyZone != "crawlledger_example_193511d5_emergency" {
		t.Fatalf("unexpected names: %#v", names)
	}
	if key := OpaqueRuleKey("example", "POST", "/api/search"); key != "a4a3763b9148314681e0ca55805620b3" {
		t.Fatalf("opaque key = %q", key)
	}
}

func TestDefaultStaticSignaturesMatchOnlyIntendedSyntheticRequests(t *testing.T) {
	tests := map[string]struct {
		matched []string
		benign  []string
	}{
		"env-file-scan": {
			matched: []string{"/.env", "/app/.env.production?download=1"},
			benign:  []string{"/dotenv", "/.environment"},
		},
		"git-metadata-scan": {
			matched: []string{"/.git/config", "/app/.git/HEAD"},
			benign:  []string{"/.github/workflows", "/git/config"},
		},
		"path-traversal-scan": {
			matched: []string{
				"/a/../etc/passwd", "/a/%2e%2e/etc/passwd", "/a%2f..%2fetc/passwd", `/a\..\etc`,
			},
			benign: []string{"/api/v1..2", "/notes/.../index"},
		},
		"log4shell-probe": {
			matched: []string{"/search?value=${jndi:ldap://192.0.2.1/a}"},
			benign:  []string{"/search?value=jndi", "/${jndi-safe}"},
		},
	}
	patterns := make(map[string]*regexp.Regexp, len(staticSignatures))
	for _, signature := range staticSignatures {
		if _, exists := tests[signature.id]; !exists {
			continue
		}
		patterns[signature.id] = regexp.MustCompile("(?i)" + strings.TrimPrefix(signature.pattern, "~*"))
	}
	for identifier, test := range tests {
		pattern := patterns[identifier]
		for _, requestURI := range test.matched {
			if !pattern.MatchString(requestURI) {
				t.Errorf("%s did not match %q", identifier, requestURI)
			}
		}
		for _, requestURI := range test.benign {
			if pattern.MatchString(requestURI) {
				t.Errorf("%s matched benign %q", identifier, requestURI)
			}
		}
	}
}

func TestRenderActiveMapIsCanonicalAndLongestPrefixFirst(t *testing.T) {
	config := nginxTestConfig()
	config.Nginx.ManagedDir = t.TempDir()
	empty, err := RenderActiveMap(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(empty) != "# CrawlLedger active map v1 site=example\n" {
		t.Fatalf("unexpected empty map: %q", empty)
	}
	rules := []ApplyRule{
		{Method: "POST", PathPrefix: "/api"},
		{Method: "POST", PathPrefix: "/api/search"},
	}
	active, err := RenderActiveMap(config, rules)
	if err != nil {
		t.Fatal(err)
	}
	expected := "# CrawlLedger active map v1 site=example\n" +
		"    \"~^POST\\\\|/api/search(?:/|\\\\z)\" \"a4a3763b9148314681e0ca55805620b3\";\n" +
		"    \"~^POST\\\\|/api(?:/|\\\\z)\" \"59c75362d921afcbad8909d18a4dcd2f\";\n"
	if string(active) != expected {
		t.Fatalf("unexpected active map:\n%s\nwant:\n%s", active, expected)
	}
}

func TestRenderProtectionIncludesStaticDenyAndBurstModes(t *testing.T) {
	requireNginxPathSemantics(t)
	config := nginxTestConfig()
	httpInclude, serverInclude, err := RenderProtectionIncludes(config)
	if err != nil {
		t.Fatal(err)
	}
	httpText := string(httpInclude)
	for _, fragment := range []string{
		"# CrawlLedger protect http v1 site=example\n",
		"map \"$request_method|$uri\" $crawlledger_example_193511d5_emergency_key {",
		"include \"/etc/nginx/crawlledger/example/crawlledger-active.map\";",
		"zone=crawlledger_example_193511d5_emergency:1m rate=10r/s;",
		"\\\\.env",
		"\\\\.git",
		"%2e%2e",
		`\\x24\\{jndi:`,
	} {
		if !strings.Contains(httpText, fragment) {
			t.Fatalf("HTTP include is missing %q:\n%s", fragment, httpText)
		}
	}
	serverText := string(serverInclude)
	if !strings.Contains(serverText, "return 403;") ||
		!strings.Contains(serverText, "limit_req_status 429;") ||
		!strings.Contains(serverText, "burst=20 nodelay;") {
		t.Fatalf("unexpected server include:\n%s", serverText)
	}
	config.Action.Burst = 0
	_, serverInclude, err = RenderProtectionIncludes(config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serverInclude), "burst=") || strings.Contains(string(serverInclude), "nodelay") {
		t.Fatalf("zero burst rendered burst options:\n%s", serverInclude)
	}
}

func TestRenderActiveMapRejectsUnsafeOrDuplicateActions(t *testing.T) {
	config := nginxTestConfig()
	config.Nginx.ManagedDir = t.TempDir()
	tests := [][]ApplyRule{
		{{Method: "GET", PathPrefix: "/health"}},
		{{Method: "GET", PathPrefix: "/api%2fsearch"}},
		{{Method: "GET", PathPrefix: "/api"}, {Method: "GET", PathPrefix: "/api"}},
	}
	for _, rules := range tests {
		if _, err := RenderActiveMap(config, rules); err == nil {
			t.Fatalf("unsafe active map accepted: %#v", rules)
		}
	}
}

func TestRenderActiveMapQuotesEveryAllowedPunctuation(t *testing.T) {
	config := nginxTestConfig()
	config.Nginx.ManagedDir = t.TempDir()
	path := "/a!\"$&'()+,-.:;<=>@[]^_`|~"
	if !domain.ValidActionable(path) {
		t.Fatal("test path is not actionable")
	}
	active, err := RenderActiveMap(config, []ApplyRule{{Method: "GET-X_1", PathPrefix: path}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(active)
	if strings.Count(text, "\n") != 2 || !strings.Contains(text, `\"`) ||
		!strings.Contains(text, `\\x24`) || strings.Contains(text, `\$`) {
		t.Fatalf("allowed punctuation was not safely quoted: %q", text)
	}
}

func nginxTestConfig() Config {
	config := testDetectorConfig()
	config.Nginx.ManagedDir = "/etc/nginx/crawlledger/example"
	config.StaticDeny.Enabled = []string{
		"env-file-scan", "git-metadata-scan", "path-traversal-scan", "log4shell-probe",
	}
	return config
}

func requireNginxPathSemantics(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Nginx live rendering uses Linux paths")
	}
}
