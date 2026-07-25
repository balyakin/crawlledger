package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"

	"github.com/balyakin/crawlledger/internal/atomicfile"
)

type Artifact struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Privacy struct {
	RawLinesRetained bool     `json:"raw_lines_retained"`
	HMACKeyRetained  bool     `json:"hmac_key_retained"`
	Anonymous        bool     `json:"anonymous"`
	ResidualRisks    []string `json:"residual_risks"`
}

type Manifest struct {
	SchemaVersion  int        `json:"schema_version"`
	AnalysisID     string     `json:"analysis_id"`
	ToolVersion    string     `json:"tool_version"`
	CatalogVersion string     `json:"catalog_version"`
	Status         string     `json:"status"`
	Artifacts      []Artifact `json:"artifacts"`
	Privacy        Privacy    `json:"privacy"`
}

func InspectArtifacts(ctx context.Context, root *os.Root, names ...string) ([]Artifact, error) {
	result := make([]Artifact, 0, len(names))
	for _, name := range names {
		expected, err := root.Lstat(name)
		if err != nil || !expected.Mode().IsRegular() || expected.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("artifact is not a regular file")
		}
		file, err := root.Open(name)
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || !os.SameFile(expected, info) {
			_ = file.Close()
			return nil, errors.New("artifact changed while opening")
		}
		hash := sha256.New()
		written, err := io.Copy(hash, &contextReader{ctx: ctx, reader: file})
		if err != nil || written != info.Size() {
			_ = file.Close()
			return nil, errors.Join(errors.New("artifact changed while reading"), err)
		}
		if err := file.Close(); err != nil {
			return nil, err
		}
		result = append(result, Artifact{Name: name, Bytes: info.Size(), SHA256: hex.EncodeToString(hash.Sum(nil))})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func WriteManifest(ctx context.Context, root *os.Root, manifest Manifest) ([]string, error) {
	return atomicfile.WriteNew(ctx, root, "manifest.json", 0o600, func(writer io.Writer) error {
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(true)
		return encoder.Encode(manifest)
	})
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(buffer)
	if err == nil {
		err = r.ctx.Err()
	}
	return read, err
}
