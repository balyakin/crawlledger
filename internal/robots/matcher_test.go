package robots

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "robots.txt")
	if err := os.WriteFile(path, []byte("User-agent: ExampleBot\nDisallow: /private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	matcher, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, err := matcher.Allowed("ExampleBot", "/private/data"); err != nil || allowed {
		t.Fatalf("private path allowed: %v %v", allowed, err)
	}
	if allowed, err := matcher.Allowed("ExampleBot", "/public"); err != nil || !allowed {
		t.Fatalf("public path denied: %v %v", allowed, err)
	}
	if allowed, err := matcher.Allowed("ExampleBot", "https://site.example/private/data?q=1"); err != nil || allowed {
		t.Fatalf("absolute-form private path allowed: %v %v", allowed, err)
	}
}
