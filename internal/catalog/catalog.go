package catalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/balyakin/crawlledger/internal/domain"
)

const Version = "ai-robots-txt:a0fed45f0eb6723597028b49d5e0990dd4c41920+crawlledger-v1"

type Entry struct {
	Name             string              `json:"name"`
	Token            string              `json:"token"`
	Category         domain.TrafficClass `json:"category"`
	ProtectedDefault bool                `json:"protected_default"`
	Source           string              `json:"source"`
	SourceVersion    string              `json:"source_version"`
}

type Catalog struct {
	version string
	entries []Entry
	byName  map[string]Entry
}

func load(data []byte) (*Catalog, error) {
	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("decode embedded catalog: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("embedded catalog is empty")
	}
	names := make(map[string]struct{}, len(entries))
	tokens := make(map[string]struct{}, len(entries))
	byName := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		nameFold, tokenFold := strings.ToLower(entry.Name), strings.ToLower(entry.Token)
		if len(entry.Name) < 1 || len(entry.Name) > 128 || !utf8.ValidString(entry.Name) ||
			len(entry.Token) < 1 || len(entry.Token) > 128 || !printableASCII(entry.Token) ||
			!entry.Category.Claimed() || entry.Source == "" || entry.SourceVersion == "" {
			return nil, errors.New("invalid embedded catalog entry")
		}
		if _, exists := names[nameFold]; exists {
			return nil, errors.New("duplicate embedded catalog name")
		}
		if _, exists := tokens[tokenFold]; exists {
			return nil, errors.New("duplicate embedded catalog token")
		}
		names[nameFold] = struct{}{}
		tokens[tokenFold] = struct{}{}
		byName[entry.Name] = entry
	}
	sort.Slice(entries, func(i, j int) bool {
		if len(entries[i].Token) != len(entries[j].Token) {
			return len(entries[i].Token) > len(entries[j].Token)
		}
		return entries[i].Name < entries[j].Name
	})
	return &Catalog{version: Version, entries: entries, byName: byName}, nil
}

func (c *Catalog) Version() string { return c.version }

func (c *Catalog) Match(userAgent string) *domain.CrawlerClaim {
	claim, _ := c.MatchWithAmbiguity(userAgent)
	return claim
}

func (c *Catalog) MatchWithAmbiguity(userAgent string) (*domain.CrawlerClaim, bool) {
	lower := strings.ToLower(userAgent)
	var claim *domain.CrawlerClaim
	matches := 0
	for _, entry := range c.entries {
		token := strings.ToLower(entry.Token)
		matched := false
		for start := 0; ; {
			index := strings.Index(lower[start:], token)
			if index < 0 {
				break
			}
			index += start
			end := index + len(token)
			if boundary(lower, index-1) && boundary(lower, end) {
				matched = true
				break
			}
			start = index + 1
		}
		if matched {
			matches++
			if claim == nil {
				claim = &domain.CrawlerClaim{
					Name: entry.Name, Category: entry.Category, ProtectedDefault: entry.ProtectedDefault,
				}
			}
		}
	}
	return claim, matches > 1
}

func (c *Catalog) ByName(name string) (Entry, bool) {
	entry, ok := c.byName[name]
	return entry, ok
}

func (c *Catalog) EntriesByCategory(category domain.TrafficClass) []Entry {
	result := make([]Entry, 0)
	for _, entry := range c.entries {
		if entry.Category == category {
			result = append(result, entry)
		}
	}
	return result
}

func (c *Catalog) Entries() []Entry { return append([]Entry(nil), c.entries...) }

func printableASCII(value string) bool {
	for _, r := range value {
		if r < 0x20 || r > 0x7e {
			return false
		}
	}
	return true
}

func boundary(value string, index int) bool {
	if index < 0 || index >= len(value) {
		return true
	}
	switch value[index] {
	case ' ', '/', ';', '(', ')', '+':
		return true
	default:
		return false
	}
}
