package aggregate

import "github.com/balyakin/crawlledger/internal/domain"

type UARow struct {
	ID               int64
	Hash             string
	ClaimedCrawler   *string
	ClaimedCategory  *domain.TrafficClass
	ProtectedDefault bool
	Overflow         bool
}

type RouteRow struct {
	ID               int64
	Route            string
	ActionablePrefix *string
	Overflow         bool
}

type CellRow struct {
	BucketMinuteUS     int64
	RouteID            int64
	UAID               int64
	PrimaryClass       domain.TrafficClass
	Method             string
	Status             int
	CacheState         domain.CacheState
	Requests           int64
	BytesSent          int64
	RequestDurationUS  *int64
	RequestSamples     int64
	UpstreamDurationUS *int64
	UpstreamSamples    int64
	RefererPresent     int64
}

type RouteStatsRow struct {
	RouteID            int64
	Requests           int64
	QueryRequests      int64
	Status404          int64
	CacheMisses        int64
	CacheSamples       int64
	BytesSent          int64
	UpstreamDurationUS *int64
	UpstreamSamples    int64
	DistinctClientsKMV []byte
	DistinctURLsKMV    []byte
	DistinctQueriesKMV []byte
}

type SubjectRow struct {
	ClientKey         string
	UAID              int64
	Claimed           bool
	Requests          int64
	Status4xx         int64
	NoReferer         int64
	ProbeRequests     int64
	RobotsViolations  int64
	DistinctRoutesKMV []byte
	FirstSeenUS       int64
	LastSeenUS        int64
}

type RateImpactRow struct {
	UAID                   int64
	PrimaryClass           domain.TrafficClass
	Profile                string
	ModeledRequests        int64
	AllowedRequests        int64
	LimitedRequests        int64
	AllowedBytes           int64
	LimitedBytes           int64
	LimitedUpstreamUS      *int64
	LimitedUpstreamSamples int64
}

type RobotsRow struct {
	UAID, RouteID int64
	Requests      int64
}

type QueryKeyRow struct {
	RouteID  int64
	Key      string
	Requests int64
}

type ProbeRow struct {
	ProbeID  string
	RouteID  int64
	Requests int64
}

type Batch struct {
	UserAgents       []UARow
	Routes           []RouteRow
	Cells            []CellRow
	RouteStats       []RouteStatsRow
	Subjects         []SubjectRow
	RateImpacts      []RateImpactRow
	RobotsViolations []RobotsRow
	QueryKeys        []QueryKeyRow
	ProbeHits        []ProbeRow
}

func (b Batch) Empty() bool {
	return len(b.UserAgents)+len(b.Routes)+len(b.Cells)+len(b.RouteStats)+len(b.Subjects)+
		len(b.RateImpacts)+len(b.RobotsViolations)+len(b.QueryKeys)+len(b.ProbeHits) == 0
}

type Summary = domain.AnalysisSummary
