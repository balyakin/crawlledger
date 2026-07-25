package classify

import (
	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/normalize"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/robots"
)

type Classifier struct {
	catalog    *catalog.Catalog
	robots     *robots.Matcher
	normalizer *normalize.Normalizer
}

func New(catalogValue *catalog.Catalog, robotsMatcher *robots.Matcher, normalizer *normalize.Normalizer) *Classifier {
	return &Classifier{catalog: catalogValue, robots: robotsMatcher, normalizer: normalizer}
}

func (c *Classifier) Classify(record parser.RawRecord) (domain.Event, error) {
	event, _, err := c.ClassifyWithWarnings(record)
	return event, err
}

func (c *Classifier) ClassifyWithWarnings(record parser.RawRecord) (domain.Event, []string, error) {
	claim, ambiguous := c.catalog.MatchWithAmbiguity(record.UserAgent)
	probes := MatchProbes(record.Method, record.RequestURI, record.Status)
	var allowed *bool
	if claim != nil && c.robots != nil {
		value, err := c.robots.Allowed(claim.Name, record.RequestURI)
		if err != nil {
			return domain.Event{}, nil, err
		}
		allowed = &value
	}
	event, err := c.normalizer.Normalize(record, normalize.Facts{
		Claim: claim, SecurityProbeIDs: probes, RobotsAllowed: allowed,
	})
	if err != nil {
		return domain.Event{}, nil, err
	}
	warnings := []string{}
	if ambiguous {
		warnings = append(warnings, "ambiguous_user_agent_observed")
	}
	return event, warnings, nil
}
