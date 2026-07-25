package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/jsonstrict"
	"github.com/balyakin/crawlledger/internal/report"
	sqlitestore "github.com/balyakin/crawlledger/internal/store/sqlite"
)

type verifiedWorkspace struct {
	path         string
	manifest     report.Manifest
	manifestHash string
	database     io.Closer
	store        *sqlitestore.Store
}

type verifiedDatabase struct {
	database io.Closer
	source   io.Closer
	cleanup  func() error
}

func (d *verifiedDatabase) Close() error {
	return errors.Join(d.database.Close(), d.source.Close(), d.cleanup())
}

func openWorkspace(ctx context.Context, path string) (*verifiedWorkspace, error) {
	clean := filepath.Clean(path)
	info, err := os.Lstat(clean)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("workspace must be a non-symlink directory")
	}
	root, err := os.OpenRoot(clean)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	manifestData, err := readRootFile(root, "manifest.json", 1<<20)
	if err != nil {
		return nil, err
	}
	if err := requireWorkspaceManifestKeys(manifestData); err != nil {
		return nil, err
	}
	var manifest report.Manifest
	if err := jsonstrict.Decode(manifestData, &manifest); err != nil {
		return nil, err
	}
	if err := validateWorkspaceManifest(manifest); err != nil {
		return nil, err
	}
	if err := verifyWorkspaceEntries(root, manifest); err != nil {
		return nil, err
	}
	var databaseSource *os.File
	for _, artifact := range manifest.Artifacts {
		var size int64
		var digest string
		if artifact.Name == "analysis.sqlite" {
			databaseSource, size, digest, err = openAndHashRootFile(ctx, root, artifact.Name)
		} else {
			size, digest, err = hashRootFile(ctx, root, artifact.Name)
		}
		if err != nil || size != artifact.Bytes || digest != artifact.SHA256 {
			if databaseSource != nil {
				_ = databaseSource.Close()
			}
			return nil, errors.New("workspace artifact integrity mismatch")
		}
	}
	if databaseSource == nil {
		return nil, errors.New("workspace database is missing")
	}
	database, cleanup, err := sqlitestore.OpenReadOnlyFile(ctx, databaseSource)
	if err != nil {
		_ = databaseSource.Close()
		return nil, err
	}
	closer := &verifiedDatabase{database: database, source: databaseSource, cleanup: cleanup}
	store := sqlitestore.NewForAnalysis(database, manifest.AnalysisID)
	if err := store.VerifyCompleted(ctx, manifest.AnalysisID, manifest.CatalogVersion); err != nil {
		_ = closer.Close()
		return nil, err
	}
	if _, err := root.Lstat("analysis.sqlite-wal"); !errors.Is(err, os.ErrNotExist) {
		_ = closer.Close()
		return nil, errors.New("workspace has a WAL file")
	}
	if _, err := root.Lstat("analysis.sqlite-shm"); !errors.Is(err, os.ErrNotExist) {
		_ = closer.Close()
		return nil, errors.New("workspace has a shared-memory file")
	}
	sum := sha256.Sum256(manifestData)
	return &verifiedWorkspace{
		path: clean, manifest: manifest, manifestHash: hex.EncodeToString(sum[:]),
		database: closer, store: store,
	}, nil
}

func requireWorkspaceManifestKeys(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return errors.New("workspace manifest must be an object")
	}
	for _, key := range []string{
		"schema_version", "analysis_id", "tool_version", "catalog_version", "status",
		"artifacts", "privacy",
	} {
		if raw, ok := top[key]; !ok || jsonIsNull(raw) {
			return errors.New("workspace manifest is missing required fields")
		}
	}
	var artifacts []map[string]json.RawMessage
	if err := json.Unmarshal(top["artifacts"], &artifacts); err != nil || artifacts == nil {
		return errors.New("workspace artifacts must be an array")
	}
	for _, artifact := range artifacts {
		for _, key := range []string{"name", "bytes", "sha256"} {
			if raw, ok := artifact[key]; !ok || jsonIsNull(raw) {
				return errors.New("workspace artifact is missing required fields")
			}
		}
	}
	var privacy map[string]json.RawMessage
	if err := json.Unmarshal(top["privacy"], &privacy); err != nil || privacy == nil {
		return errors.New("workspace privacy must be an object")
	}
	for _, key := range []string{
		"raw_lines_retained", "hmac_key_retained", "anonymous", "residual_risks",
	} {
		if raw, ok := privacy[key]; !ok || jsonIsNull(raw) {
			return errors.New("workspace privacy is missing required fields")
		}
	}
	return nil
}

func jsonIsNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func (w *verifiedWorkspace) Close() error { return w.database.Close() }

func validateWorkspaceManifest(manifest report.Manifest) error {
	if manifest.SchemaVersion != 1 || manifest.Status != "completed" ||
		!strings.HasPrefix(manifest.AnalysisID, "an_") ||
		!lowerHex(manifest.AnalysisID[3:], 32) || manifest.ToolVersion == "" ||
		manifest.CatalogVersion != catalog.Version ||
		manifest.Artifacts == nil || manifest.Privacy.ResidualRisks == nil ||
		manifest.Privacy.RawLinesRetained || manifest.Privacy.HMACKeyRetained ||
		manifest.Privacy.Anonymous {
		return errors.New("invalid workspace manifest")
	}
	expected := []string{"analysis.sqlite", "report.html", "report.json"}
	if len(manifest.Artifacts) != len(expected) {
		return errors.New("workspace artifact set mismatch")
	}
	for index, artifact := range manifest.Artifacts {
		if artifact.Name != expected[index] || artifact.Bytes < 0 || !lowerHex(artifact.SHA256, 64) {
			return errors.New("workspace artifacts must be sorted and complete")
		}
	}
	return nil
}

func lowerHex(value string, size int) bool {
	if len(value) != size || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func verifyWorkspaceEntries(root *os.Root, manifest report.Manifest) error {
	allowed := map[string]struct{}{"manifest.json": {}}
	targets := make([]os.FileInfo, 0, len(manifest.Artifacts)+1)
	for _, artifact := range manifest.Artifacts {
		allowed[artifact.Name] = struct{}{}
		info, err := root.Lstat(artifact.Name)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("workspace artifact is not a regular file")
		}
		targets = append(targets, info)
	}
	manifestInfo, err := root.Lstat("manifest.json")
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("workspace manifest is not a regular file")
	}
	targets = append(targets, manifestInfo)
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil || closeErr != nil {
		return errors.Join(readErr, closeErr)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := allowed[name]; ok {
			continue
		}
		if name == "analysis.sqlite-wal" || name == "analysis.sqlite-shm" {
			return errors.New("workspace contains SQLite side files")
		}
		if !strings.HasPrefix(name, ".crawlledger-") {
			return errors.New("workspace contains an unknown entry")
		}
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("invalid workspace cleanup residue")
		}
		linked := false
		for _, target := range targets {
			linked = linked || os.SameFile(info, target)
		}
		if !linked {
			return errors.New("unrecognized workspace cleanup residue")
		}
	}
	return nil
}

func readRootFile(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() > limit {
		return nil, errors.New("invalid bounded input file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("input file changed while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot read bounded input file")
	}
	return data, nil
}

func hashRootFile(ctx context.Context, root *os.Root, name string) (int64, string, error) {
	file, size, digest, err := openAndHashRootFile(ctx, root, name)
	if file != nil {
		err = errors.Join(err, file.Close())
	}
	return size, digest, err
}

func openAndHashRootFile(ctx context.Context, root *os.Root, name string) (*os.File, int64, string, error) {
	info, err := root.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, "", errors.New("invalid artifact")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, 0, "", err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, 0, "", errors.New("artifact changed while opening")
	}
	hash := sha256.New()
	written, copyErr := io.Copy(hash, &anchoredContextReader{ctx: ctx, reader: file})
	if copyErr != nil || written != info.Size() {
		_ = file.Close()
		return nil, 0, "", errors.Join(copyErr, errors.New("artifact changed while reading"))
	}
	return file, written, hex.EncodeToString(hash.Sum(nil)), nil
}

type anchoredContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *anchoredContextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(buffer)
	if err == nil {
		err = r.ctx.Err()
	}
	return read, err
}

func ensureOutsideWorkspace(target, workspace string) error {
	if pathInside(target, workspace) {
		return errors.New("output must be outside workspace")
	}
	workspaceAbsolute, err := filepath.Abs(workspace)
	if err != nil {
		return err
	}
	workspaceReal, err := filepath.EvalSymlinks(workspaceAbsolute)
	if err != nil {
		return err
	}
	targetAbsolute, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	parent := filepath.Dir(targetAbsolute)
	parentReal, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(workspaceReal, parentReal)
	if err != nil {
		return err
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("output parent is inside workspace")
	}
	return nil
}
