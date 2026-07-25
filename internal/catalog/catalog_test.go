package catalog

import (
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
)

func TestEmbeddedAndBoundaries(t *testing.T) {
	value, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	if value.Version() != Version || len(value.Entries()) < 150 {
		t.Fatalf("unexpected embedded catalog: %s, %d", value.Version(), len(value.Entries()))
	}
	claim := value.Match("Mozilla/5.0 GPTBot/1.0")
	if claim == nil || claim.Name != "GPTBot" || claim.Category != domain.ClassClaimedAICrawler {
		t.Fatalf("GPTBot not classified: %#v", claim)
	}
	if value.Match("NotGPTBotSuffix") != nil {
		t.Fatal("substring matched without boundary")
	}
	claim = value.Match("applebot/1.0")
	if claim == nil || !claim.ProtectedDefault || claim.Category != domain.ClassClaimedSearchCrawler {
		t.Fatalf("Applebot override missing: %#v", claim)
	}
	claim = value.Match("Applebot-Extended/1.0")
	if claim == nil || claim.Name != "Applebot-Extended" {
		t.Fatalf("longest token did not win: %#v", claim)
	}
	claim, ambiguous := value.MatchWithAmbiguity("Googlebot GPTBot")
	if claim == nil || claim.Name != "Googlebot" || !ambiguous {
		t.Fatalf("multi-token ambiguity not reported: %#v, %t", claim, ambiguous)
	}
}
