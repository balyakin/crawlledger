package policy

import (
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
)

var identifier = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func Validate(value domain.Policy, catalogValue *catalog.Catalog) error {
	if value.SchemaVersion != 1 || !identifier.MatchString(value.Name) {
		return errors.New("invalid policy schema or name")
	}
	if len(value.Rules) < 1 || len(value.Rules) > 100 {
		return errors.New("policy must contain 1 to 100 rules")
	}
	ids := make(map[string]struct{}, len(value.Rules))
	caddyNames := make(map[string]struct{}, len(value.Rules))
	expanded := make([]map[string]struct{}, len(value.Rules))
	for index, rule := range value.Rules {
		if !identifier.MatchString(rule.ID) {
			return errors.New("invalid rule ID")
		}
		if _, exists := ids[rule.ID]; exists {
			return errors.New("duplicate rule ID")
		}
		ids[rule.ID] = struct{}{}
		caddyName := strings.ReplaceAll(rule.ID, "-", "_")
		if _, exists := caddyNames[caddyName]; exists {
			return errors.New("rule IDs collide as Caddy matcher names")
		}
		caddyNames[caddyName] = struct{}{}
		for _, values := range [][]string{rule.Match.CrawlerNames, rule.Match.PathPrefixes, rule.Match.Methods} {
			if len(values) > 50 || !sortedUnique(values) {
				return errors.New("matcher arrays must be sorted unique and contain at most 50 values")
			}
		}
		categories := make([]string, len(rule.Match.Categories))
		for i, category := range rule.Match.Categories {
			categories[i] = string(category)
			if !category.Claimed() {
				return errors.New("invalid policy category")
			}
		}
		if len(categories) > 50 || !sortedUnique(categories) {
			return errors.New("category array must be sorted unique")
		}
		for _, name := range rule.Match.CrawlerNames {
			if _, ok := catalogValue.ByName(name); !ok {
				return errors.New("unknown crawler name")
			}
		}
		for _, path := range rule.Match.PathPrefixes {
			if !validPath(path) {
				return errors.New("invalid policy path prefix")
			}
		}
		for _, method := range rule.Match.Methods {
			if !validMethod(method) {
				return errors.New("invalid policy method")
			}
		}
		if !rule.Action.Kind.Valid() {
			return errors.New("invalid policy action")
		}
		nonempty := len(rule.Match.CrawlerNames)+len(rule.Match.Categories)+len(rule.Match.PathPrefixes)+len(rule.Match.Methods) > 0
		switch rule.Action.Kind {
		case domain.ActionAllow, domain.ActionDeny:
			if !nonempty || rule.Action.RateProfile != nil || rule.Action.CacheTTLSeconds != nil {
				return errors.New("invalid allow/deny action")
			}
		case domain.ActionRateLimit:
			if len(rule.Match.CrawlerNames)+len(rule.Match.Categories) == 0 ||
				len(rule.Match.PathPrefixes)+len(rule.Match.Methods) != 0 ||
				rule.Action.RateProfile == nil || rule.Action.CacheTTLSeconds != nil ||
				!validProfile(*rule.Action.RateProfile) {
				return errors.New("invalid rate-limit action")
			}
		case domain.ActionCache:
			if len(rule.Match.PathPrefixes) == 0 || len(rule.Match.CrawlerNames)+len(rule.Match.Categories) != 0 ||
				rule.Action.RateProfile != nil || rule.Action.CacheTTLSeconds == nil ||
				*rule.Action.CacheTTLSeconds < 1 || *rule.Action.CacheTTLSeconds > 86400 ||
				len(rule.Match.Methods) == 0 {
				return errors.New("invalid cache action")
			}
			for _, method := range rule.Match.Methods {
				if method != "GET" && method != "HEAD" {
					return errors.New("cache methods must be GET or HEAD")
				}
			}
		}
		expanded[index] = expand(rule.Match, catalogValue)
		if rule.Action.Kind == domain.ActionRateLimit {
			for previous := 0; previous < index; previous++ {
				if intersects(expanded[index], expanded[previous]) {
					return errors.New("rate rule overlaps an earlier rule")
				}
			}
		}
	}
	return nil
}

func validPath(value string) bool {
	if len(value) < 1 || len(value) > 256 || value[0] != '/' || strings.Contains(value, "//") ||
		strings.Contains(value, "..") || strings.ContainsAny(value, `\%?#*{} `) {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func validMethod(value string) bool {
	if len(value) < 1 || len(value) > 16 {
		return false
	}
	for i, r := range value {
		if r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9' || i > 0 && (r == '_' || r == '-') {
			continue
		}
		return false
	}
	return true
}

func validProfile(value string) bool {
	return value == "gentle" || value == "standard" || value == "strict"
}

func sortedUnique(values []string) bool {
	return sort.StringsAreSorted(values) && !hasDuplicate(values)
}

func hasDuplicate(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return true
		}
	}
	return false
}

func expand(match domain.PolicyMatch, catalogValue *catalog.Catalog) map[string]struct{} {
	result := make(map[string]struct{})
	if len(match.CrawlerNames)+len(match.Categories) == 0 {
		for _, entry := range catalogValue.Entries() {
			result[entry.Name] = struct{}{}
		}
		result["{unclaimed}"] = struct{}{}
		return result
	}
	for _, name := range match.CrawlerNames {
		result[name] = struct{}{}
	}
	for _, category := range match.Categories {
		for _, entry := range catalogValue.EntriesByCategory(category) {
			result[entry.Name] = struct{}{}
		}
	}
	return result
}

func intersects(left, right map[string]struct{}) bool {
	for value := range left {
		if _, ok := right[value]; ok {
			return true
		}
	}
	return false
}
