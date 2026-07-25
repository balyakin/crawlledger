package policy

import (
	"strings"

	"github.com/balyakin/crawlledger/internal/domain"
)

func Matches(rule domain.PolicyRule, cell domain.PolicyCell) bool {
	if len(rule.Match.CrawlerNames) > 0 {
		if cell.ClaimName == nil || !contains(rule.Match.CrawlerNames, *cell.ClaimName) {
			return false
		}
	}
	if len(rule.Match.Categories) > 0 {
		if cell.ClaimCategory == nil || !containsClass(rule.Match.Categories, *cell.ClaimCategory) {
			return false
		}
	}
	if len(rule.Match.PathPrefixes) > 0 {
		if cell.ActionablePrefix == nil {
			return false
		}
		matched := false
		for _, prefix := range rule.Match.PathPrefixes {
			if segmentPrefix(*cell.ActionablePrefix, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return len(rule.Match.Methods) == 0 || contains(rule.Match.Methods, cell.Method)
}

func segmentPrefix(value, prefix string) bool {
	if prefix == "/" {
		return strings.HasPrefix(value, "/")
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return value == prefix || strings.HasPrefix(value, prefix+"/")
}

func contains(values []string, target string) bool {
	index := sortSearch(values, target)
	return index < len(values) && values[index] == target
}

func containsClass(values []domain.TrafficClass, target domain.TrafficClass) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func sortSearch(values []string, target string) int {
	low, high := 0, len(values)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if values[middle] < target {
			low = middle + 1
		} else {
			high = middle
		}
	}
	return low
}
