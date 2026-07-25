package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maxConfigBytes int64 = 1 << 20
const maxJSONDepth = 128

func Load(path string) (Config, error) {
	if path == "" {
		value := Default()
		return value, value.Validate()
	}
	data, err := readAnchored(path, maxConfigBytes)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := requireConfigKeys(data); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var value Config
	if err := decoder.Decode(&value); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Config{}, errors.New("decode config: trailing JSON value")
		}
		return Config{}, fmt.Errorf("decode config trailer: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Config{}, fmt.Errorf("validate config: %w", err)
	}
	return value, nil
}

func requireConfigKeys(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return errors.New("config must be an object")
	}
	for _, key := range []string{"schema_version", "limits", "thresholds", "costs"} {
		if raw, ok := top[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("config.%s is required", key)
		}
	}
	groups := []struct {
		name string
		keys []string
	}{
		{"limits", []string{
			"max_line_bytes", "max_uncompressed_bytes", "max_gzip_ratio", "max_routes",
			"max_user_agents", "max_rate_subjects", "max_batch_cells", "max_saved_parse_errors",
		}},
		{"thresholds", []string{
			"crawltrap_min_requests", "crawltrap_min_url_variants", "crawltrap_variant_ratio_ppm",
			"query_min_requests", "query_min_variants", "query_variant_ratio_ppm",
			"expensive_404_min_requests", "expensive_404_ratio_ppm", "expensive_404_min_upstream_us",
			"cache_bust_min_requests", "cache_bust_miss_ratio_ppm", "automation_min_requests",
			"automation_min_routes", "automation_4xx_ratio_ppm", "automation_no_referer_ratio_ppm",
			"automation_min_probes", "automation_score_threshold",
		}},
		{"costs", []string{"monthly_hosting_kopecks", "egress_kopecks_per_gib"}},
	}
	for _, group := range groups {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(top[group.name], &object); err != nil || object == nil {
			return fmt.Errorf("config.%s must be an object", group.name)
		}
		for _, key := range group.keys {
			if raw, ok := object[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("config.%s.%s is required", group.name, key)
			}
		}
	}
	return nil
}

func readAnchored(path string, limit int64) ([]byte, error) {
	parent, name := filepath.Split(filepath.Clean(path))
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("invalid file name")
	}
	if parent == "" {
		parent = "."
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("file must be regular and non-symlink")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, statErr := file.Stat()
	if statErr != nil || !os.SameFile(info, opened) {
		return nil, errors.Join(statErr, errors.New("file changed while opening"), file.Close())
	}
	if opened.Size() > limit {
		return nil, errors.Join(fmt.Errorf("file exceeds %d bytes", limit), file.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	return data, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
