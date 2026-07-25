package normalize

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"sort"
)

func (n *Normalizer) normalizeQuery(uri *url.URL) ([]string, *string, error) {
	if uri.RawQuery == "" {
		return []string{}, nil, nil
	}
	values, err := url.ParseQuery(uri.RawQuery)
	if err != nil {
		return nil, nil, errInvalidURI
	}
	type tuple struct {
		key, valueHash string
	}
	keys := make([]string, 0, len(values))
	tuples := make([]tuple, 0)
	for key, entries := range values {
		safe := safeQueryKey(key)
		if safe == "" {
			sum := n.hmac("query-key", []byte(key))
			safe = "{key-" + hex.EncodeToString(sum[:4]) + "}"
		}
		keys = append(keys, safe)
		for _, value := range entries {
			sum := n.hmac("query-value", []byte(value))
			tuples = append(tuples, tuple{key: safe, valueHash: hex.EncodeToString(sum[:])})
		}
	}
	sort.Strings(keys)
	keys = dedupe(keys)
	if len(keys) > 32 {
		keys = append(keys[:31], "{overflow}")
	}
	sort.Slice(tuples, func(i, j int) bool {
		if tuples[i].key != tuples[j].key {
			return tuples[i].key < tuples[j].key
		}
		return tuples[i].valueHash < tuples[j].valueHash
	})
	var canonical bytes.Buffer
	var length [4]byte
	for _, item := range tuples {
		for _, value := range []string{item.key, item.valueHash} {
			binary.BigEndian.PutUint32(length[:], uint32(len(value)))
			canonical.Write(length[:])
			canonical.WriteString(value)
		}
	}
	sum := n.hmac("query", canonical.Bytes())
	fingerprint := hex.EncodeToString(sum[:16])
	return keys, &fingerprint, nil
}

func safeQueryKey(key string) string {
	if len(key) < 1 || len(key) > 64 {
		return ""
	}
	for _, r := range key {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
			r == '_' || r == '.' || r == '-' {
			continue
		}
		return ""
	}
	return key
}

func dedupe(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
