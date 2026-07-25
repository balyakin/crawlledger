package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/jsonstrict"
)

const maxPolicyBytes int64 = 1 << 20

func Load(path string) (domain.Policy, error) {
	data, err := readAnchored(path, maxPolicyBytes)
	if err != nil {
		return domain.Policy{}, fmt.Errorf("read policy: %w", err)
	}
	return decode(data)
}

func decode(data []byte) (domain.Policy, error) {
	if err := requireKeys(data); err != nil {
		return domain.Policy{}, err
	}
	var value domain.Policy
	if err := jsonstrict.Decode(data, &value); err != nil {
		return domain.Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if value.Rules == nil {
		return domain.Policy{}, errors.New("policy.rules must be an array")
	}
	for _, rule := range value.Rules {
		if rule.Match.CrawlerNames == nil || rule.Match.Categories == nil ||
			rule.Match.PathPrefixes == nil || rule.Match.Methods == nil {
			return domain.Policy{}, errors.New("policy matcher arrays must not be null")
		}
	}
	return value, nil
}

func readAnchored(path string, limit int64) ([]byte, error) {
	parent, name := filepath.Split(filepath.Clean(path))
	if parent == "" {
		parent = "."
	}
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("invalid policy file name")
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
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > limit {
		return nil, errors.New("input must be a bounded regular non-symlink file")
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("policy changed while opening")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot read bounded policy")
	}
	return data, nil
}

func requireKeys(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return errors.New("policy must be an object")
	}
	for _, key := range []string{"schema_version", "name", "description", "rules"} {
		if raw, ok := top[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return fmt.Errorf("policy.%s is required", key)
		}
	}
	var rules []map[string]json.RawMessage
	if err := json.Unmarshal(top["rules"], &rules); err != nil || rules == nil {
		return errors.New("policy.rules must be an array")
	}
	for index, rule := range rules {
		for _, key := range []string{"id", "match", "action"} {
			if raw, ok := rule[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("policy.rules[%d].%s is required", index, key)
			}
		}
		var match map[string]json.RawMessage
		var action map[string]json.RawMessage
		if json.Unmarshal(rule["match"], &match) != nil || json.Unmarshal(rule["action"], &action) != nil {
			return fmt.Errorf("policy.rules[%d] matcher/action must be objects", index)
		}
		for _, key := range []string{"crawler_names", "categories", "path_prefixes", "methods"} {
			if raw, ok := match[key]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("policy.rules[%d].match.%s is required", index, key)
			}
		}
		for _, key := range []string{"kind", "rate_profile", "cache_ttl_seconds"} {
			raw, ok := action[key]
			if !ok || key == "kind" && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("policy.rules[%d].action.%s is required", index, key)
			}
		}
	}
	return nil
}
