package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestSourceArchitecture(t *testing.T) {
	root := filepath.Clean("../..")
	forbiddenMarkers := []string{"TO" + "DO", "FIX" + "ME", "panic(\"not implemented\")"}
	forbiddenPackages := map[string]bool{"utils": true, "helpers": true, "common": true, "shared": true, "misc": true}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			if forbiddenPackages[entry.Name()] && strings.Contains(filepath.ToSlash(path), "/internal/") {
				t.Errorf("forbidden package directory: %s", path)
			}
			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		full, parseErr := parser.ParseFile(token.NewFileSet(), path, data, parser.ParseComments)
		if parseErr != nil {
			return parseErr
		}
		generatedMarker := "Code " + "generated"
		if strings.Contains(string(data), generatedMarker) && !ast.IsGenerated(full) {
			t.Errorf("invalid generated marker in %s", path)
		}
		if ast.IsGenerated(full) {
			return nil
		}
		for _, marker := range forbiddenMarkers {
			if strings.Contains(string(data), marker) {
				t.Errorf("forbidden marker %q in %s", marker, path)
			}
		}
		if !strings.HasSuffix(relative, "_test.go") && strings.Contains(string(data), "VAC"+"UUM") {
			t.Errorf("VACUUM is forbidden in production source: %s", path)
		}
		for _, spec := range full.Imports {
			importPath, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			checkImport(t, relative, importPath)
		}
		if relative != "cmd/crawlledger/main.go" {
			ast.Inspect(full, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && selector.Sel.Name == "Exit" {
					t.Errorf("possible os.Exit outside main: %s", path)
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func checkImport(t *testing.T, source, imported string) {
	t.Helper()
	const module = "github.com/balyakin/crawlledger/"
	if imported == module+"cmd/crawlledger" || strings.HasPrefix(imported, module+"cmd/crawlledger/") {
		t.Errorf("%s imports command package %s", source, imported)
		return
	}
	const internal = "github.com/balyakin/crawlledger/internal/"
	if !strings.HasPrefix(imported, internal) {
		return
	}
	target := strings.TrimPrefix(imported, internal)
	source = strings.TrimPrefix(source, "internal/")
	layer := strings.Split(source, "/")[0]
	switch layer {
	case "domain":
		t.Errorf("domain imports internal package %s", target)
	case "parser":
		if strings.HasPrefix(target, "store/") || target == "report" || target == "policy" {
			t.Errorf("parser imports forbidden package %s", target)
		}
	case "report":
		if target == "parser" || target == "input" || target == "cli" {
			t.Errorf("report imports forbidden package %s", target)
		}
	case "store":
		if strings.HasPrefix(source, "store/sqlite/") &&
			(target == "cli" || target == "app" || target == "report") {
			t.Errorf("store/sqlite imports forbidden package %s", target)
		}
	case "render":
		if target == "store/sqlite" || strings.HasPrefix(target, "store/sqlite/") {
			t.Errorf("render imports forbidden package %s", target)
		}
	case "config", "apperr", "logging", "version", "atomicfile":
		if target != "" {
			t.Errorf("%s imports business package %s", layer, target)
		}
	}
}
