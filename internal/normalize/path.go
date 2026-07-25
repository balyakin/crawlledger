package normalize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	emailSegment = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	uuidSegment  = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	digits       = regexp.MustCompile(`^[0-9]+$`)
	hexSegment   = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	tokenSegment = regexp.MustCompile(`^[A-Za-z0-9_-]{24,}={0,2}$`)
)

func (n *Normalizer) normalizePath(uri *url.URL, rawURI string) (string, *string, error) {
	escaped := uri.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	rawSegments := strings.Split(escaped, "/")
	normalized := make([]string, 0, len(rawSegments))
	actionable := !strings.Contains(escaped, "%") && !strings.Contains(escaped, "//") &&
		!strings.ContainsAny(escaped, "\\\x00")
	staticCount := 0
	placeholderSeen := false
	for index, raw := range rawSegments {
		if index == 0 {
			normalized = append(normalized, "")
			continue
		}
		decoded, err := url.PathUnescape(raw)
		if err != nil || !utf8.ValidString(decoded) || containsControl(decoded) {
			return "", nil, errInvalidURI
		}
		segment := decoded
		static := true
		switch {
		case strings.ContainsAny(decoded, "/\\"):
			segment, static, actionable = "{encoded-separator}", false, false
		case decoded == "." || decoded == "..":
			segment, static, actionable = "{dot-segment}", false, false
		case emailSegment.MatchString(decoded):
			segment, static = "{email}", false
		case uuidSegment.MatchString(decoded):
			segment, static = "{uuid}", false
		case isYear(decoded):
			segment, static = "{year}", false
		case digits.MatchString(decoded):
			segment, static = "{int}", false
		case hexSegment.MatchString(decoded):
			segment, static = "{hex}", false
		case tokenSegment.MatchString(decoded):
			segment, static = "{token}", false
		case len(decoded) > 96:
			segment, static = "{long}", false
		default:
			for _, r := range decoded {
				if r > unicode.MaxASCII {
					actionable = false
				}
			}
		}
		if !placeholderSeen && static {
			staticCount = len(normalized)
		} else if !static {
			placeholderSeen = true
		}
		normalized = append(normalized, segment)
	}
	route := strings.Join(normalized, "/")
	if route == "" {
		route = "/"
	}
	if len(route) > 512 {
		sum := n.hmac("url", []byte(escaped))
		suffix := "/{truncated-" + hex.EncodeToString(sum[:8]) + "}"
		limit := 470 - len(suffix)
		cut := strings.LastIndex(route[:min(limit, len(route))], "/")
		if cut < 1 {
			cut = 1
		}
		route = route[:cut] + suffix
		actionable = false
	}
	if !actionable {
		return route, nil, nil
	}
	var prefix string
	if !placeholderSeen {
		prefix = route
	} else if staticCount == 0 {
		prefix = "/"
	} else {
		prefix = strings.Join(normalized[:staticCount+1], "/") + "/"
	}
	if len(prefix) > 256 {
		return route, nil, nil
	}
	return route, &prefix, nil
}

func isYear(value string) bool {
	if len(value) != 4 || !digits.MatchString(value) {
		return false
	}
	year, _ := strconv.Atoi(value)
	return year >= 1900 && year <= 2100
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}

func truncateHMAC(key Key, purpose, value string) string {
	hash := hmac.New(sha256.New, key[:])
	_, _ = hash.Write([]byte(purpose))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(value))
	return hex.EncodeToString(hash.Sum(nil)[:16])
}
