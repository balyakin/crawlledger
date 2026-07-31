package schemas_test

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/app"
	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/policy"
	"github.com/balyakin/crawlledger/internal/protect"
	"github.com/balyakin/crawlledger/internal/report"
)

func TestSchemas(t *testing.T) {
	types := map[string]reflect.Type{
		"config-v1.schema.json":             reflect.TypeOf(config.Config{}),
		"policy-v1.schema.json":             reflect.TypeOf(domain.Policy{}),
		"protect-apply-v1.schema.json":      reflect.TypeOf(protect.ApplyPayload{}),
		"protect-state-v1.schema.json":      reflect.TypeOf(protect.State{}),
		"protect-v1.schema.json":            reflect.TypeOf(protect.Config{}),
		"simulation-v1.schema.json":         reflect.TypeOf(domain.Simulation{}),
		"report-v1.schema.json":             reflect.TypeOf(report.Model{}),
		"sanitized-event-v1.schema.json":    reflect.TypeOf(parser.CanonicalEvent{}),
		"sanitized-manifest-v1.schema.json": reflect.TypeOf(app.SanitizedManifest{}),
		"workspace-manifest-v1.schema.json": reflect.TypeOf(report.Manifest{}),
		"render-manifest-v1.schema.json":    reflect.TypeOf(app.RenderManifest{}),
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seenIDs := make(map[string]struct{})
	seenFiles := make(map[string]struct{})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		expectedType, expected := types[entry.Name()]
		if !expected {
			t.Fatalf("unexpected schema %s", entry.Name())
		}
		seenFiles[entry.Name()] = struct{}{}
		data, err := os.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		id, ok := schema["$id"].(string)
		if !ok || id == "" {
			t.Fatalf("%s has no $id", entry.Name())
		}
		if _, duplicate := seenIDs[id]; duplicate {
			t.Fatalf("duplicate $id %s", id)
		}
		seenIDs[id] = struct{}{}
		assertClosedObjects(t, entry.Name(), schema)
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("%s has no properties", entry.Name())
		}
		got := make([]string, 0, len(properties))
		for name := range properties {
			got = append(got, name)
		}
		sort.Strings(got)
		want := jsonTags(expectedType)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s top-level properties %v, want %v", entry.Name(), got, want)
		}
	}
	if len(seenFiles) != len(types) {
		t.Fatalf("found %d schemas, want %d", len(seenFiles), len(types))
	}
}

func assertClosedObjects(t *testing.T, path string, value any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		if node["type"] == "object" {
			if node["additionalProperties"] != false {
				t.Fatalf("%s has an open object", path)
			}
			properties, propertiesOK := node["properties"].(map[string]any)
			required, requiredOK := node["required"].([]any)
			if !propertiesOK || !requiredOK || len(properties) != len(required) {
				t.Fatalf("%s does not require every property", path)
			}
			for _, name := range required {
				if _, ok := properties[name.(string)]; !ok {
					t.Fatalf("%s requires unknown property %v", path, name)
				}
			}
		}
		for key, child := range node {
			assertClosedObjects(t, path+"."+key, child)
		}
	case []any:
		for _, child := range node {
			assertClosedObjects(t, path, child)
		}
	}
}

func TestGoldenContracts(t *testing.T) {
	root := filepath.Join("..", "testdata")
	if _, err := config.Load(filepath.Join(root, "configs", "nonzero-cost.json")); err != nil {
		t.Fatal(err)
	}
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	value, err := policy.Load(filepath.Join(root, "policies", "safe.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(value, catalogValue); err != nil {
		t.Fatal(err)
	}
	if _, _, err := policy.LoadSimulation(filepath.Join(root, "golden", "simulation.json")); err != nil {
		t.Fatal(err)
	}
	for path, target := range map[string]any{
		"golden/report.json":                     &report.Model{},
		"golden/sanitized.manifest.json":         &app.SanitizedManifest{},
		"golden/workspace.manifest.json":         &report.Manifest{},
		"golden/nginx-MANIFEST.json":             &app.RenderManifest{},
		"golden/caddy-MANIFEST.json":             &app.RenderManifest{},
		"logs/canonical/sanitized.manifest.json": &app.SanitizedManifest{},
	} {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	file, err := os.Open(filepath.Join(root, "logs", "canonical", "valid.jsonl.gz"))
	if err != nil {
		t.Fatal(err)
	}
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	formatParser, _ := parser.New(parser.FormatCrawlLedgerJSON)
	scanner := bufio.NewScanner(gzipReader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		if _, err := formatParser.Parse(scanner.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	if err := errors.Join(scanner.Err(), gzipReader.Close(), file.Close()); err != nil {
		t.Fatal(err)
	}
}

func jsonTags(value reflect.Type) []string {
	result := make([]string, 0, value.NumField())
	for index := 0; index < value.NumField(); index++ {
		tag := strings.Split(value.Field(index).Tag.Get("json"), ",")[0]
		if tag != "" && tag != "-" {
			result = append(result, tag)
		}
	}
	sort.Strings(result)
	return result
}
