package aggregate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/domain"
)

type Sink interface {
	Flush(context.Context, Batch) error
}

type Aggregator struct {
	config config.Config
	sink   Sink

	routes          map[string]int64
	routeRows       map[int64]RouteRow
	uas             map[string]int64
	uaRows          map[int64]UARow
	unclaimedUAs    int
	routeOverflowID int64
	uaOverflowID    int64
	nextRouteID     int64
	nextUAID        int64

	cells        map[cellKey]*CellRow
	routeStats   map[int64]*routeAccumulator
	subjects     map[subjectKey]*subjectAccumulator
	rateSubjects map[subjectKey]*rateSubject
	rateImpacts  map[rateImpactKey]*RateImpactRow
	robots       map[[2]int64]int64
	queryKeys    map[queryKey]int64
	probes       map[probeKey]int64
	newRoutes    []RouteRow
	newUAs       []UARow
	summary      Summary
	finished     bool
}

type cellKey struct {
	minute, routeID, uaID int64
	class                 domain.TrafficClass
	method                string
	status                int
	cache                 domain.CacheState
}

type routeAccumulator struct {
	row                    RouteStatsRow
	clients, urls, queries Sketch
}

type subjectKey struct {
	client string
	uaID   int64
}

type subjectAccumulator struct {
	row    SubjectRow
	routes Sketch
}

type queryKey struct {
	routeID int64
	key     string
}

type probeKey struct {
	routeID int64
	id      string
}

func New(cfg config.Config, sink Sink) *Aggregator {
	return &Aggregator{
		config: cfg, sink: sink, routes: make(map[string]int64), routeRows: make(map[int64]RouteRow),
		uas: make(map[string]int64), uaRows: make(map[int64]UARow), nextRouteID: 1, nextUAID: 1,
		cells: make(map[cellKey]*CellRow), routeStats: make(map[int64]*routeAccumulator),
		subjects: make(map[subjectKey]*subjectAccumulator), rateSubjects: make(map[subjectKey]*rateSubject),
		rateImpacts: make(map[rateImpactKey]*RateImpactRow), robots: make(map[[2]int64]int64),
		queryKeys: make(map[queryKey]int64), probes: make(map[probeKey]int64),
	}
}

// ponytail: v1 processes records sequentially for deterministic ordering and bounded memory;
// add a measured parser pipeline only if benchmarks show CPU parsing is the bottleneck.
func (a *Aggregator) Add(ctx context.Context, event domain.Event) error {
	if a.finished {
		return errors.New("aggregator already finished")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate event: %w", err)
	}
	routeID, err := a.routeID(event)
	if err != nil {
		return err
	}
	uaID, err := a.uaID(event)
	if err != nil {
		return err
	}
	key := cellKey{
		minute: domain.MinuteBucket(event.TimestampUS), routeID: routeID, uaID: uaID,
		class: event.PrimaryClass, method: event.Method, status: event.Status, cache: event.CacheState,
	}
	cell := a.cells[key]
	if cell == nil {
		cell = &CellRow{
			BucketMinuteUS: key.minute, RouteID: routeID, UAID: uaID, PrimaryClass: key.class,
			Method: key.method, Status: key.status, CacheState: key.cache,
		}
		a.cells[key] = cell
	}
	if err := addCell(cell, event); err != nil {
		return err
	}
	if err := a.addRoute(routeID, event); err != nil {
		return err
	}
	if err := a.addSubject(uaID, event); err != nil {
		return err
	}
	if err := a.addRate(uaID, event); err != nil {
		return err
	}
	if event.RobotsAllowed != nil && !*event.RobotsAllowed {
		index := [2]int64{uaID, routeID}
		a.robots[index], err = checkedAdd(a.robots[index], 1)
		if err != nil {
			return err
		}
	}
	for _, query := range event.QueryKeys {
		index := queryKey{routeID: routeID, key: query}
		a.queryKeys[index], err = checkedAdd(a.queryKeys[index], 1)
		if err != nil {
			return err
		}
	}
	for _, probe := range event.SecurityProbeIDs {
		index := probeKey{routeID: routeID, id: probe}
		a.probes[index], err = checkedAdd(a.probes[index], 1)
		if err != nil {
			return err
		}
	}
	if err := a.addSummary(event); err != nil {
		return err
	}
	if a.batchFull() {
		return a.flush(ctx)
	}
	return nil
}

func (a *Aggregator) Finish(ctx context.Context) (Summary, error) {
	if a.finished {
		return Summary{}, errors.New("aggregator already finished")
	}
	a.finished = true
	if err := a.flush(ctx); err != nil {
		return Summary{}, err
	}
	return a.summary, nil
}

func (a *Aggregator) routeID(event domain.Event) (int64, error) {
	prefix := ""
	if event.ActionablePrefix != nil {
		prefix = *event.ActionablePrefix
	}
	identity := event.Route + "\x00" + prefix
	if id, ok := a.routes[identity]; ok {
		return id, nil
	}
	if len(a.routes) >= a.config.Limits.MaxRoutes {
		if a.routeOverflowID == 0 {
			a.routeOverflowID = a.nextRouteID
			a.nextRouteID++
			row := RouteRow{ID: a.routeOverflowID, Route: "/{overflow}", Overflow: true}
			a.routeRows[row.ID] = row
			a.newRoutes = append(a.newRoutes, row)
		}
		if err := increment(&a.summary.RouteOverflow); err != nil {
			return 0, err
		}
		return a.routeOverflowID, nil
	}
	id := a.nextRouteID
	a.nextRouteID++
	row := RouteRow{ID: id, Route: event.Route, ActionablePrefix: event.ActionablePrefix}
	a.routes[identity], a.routeRows[id] = id, row
	a.newRoutes = append(a.newRoutes, row)
	return id, nil
}

func (a *Aggregator) uaID(event domain.Event) (int64, error) {
	hash := event.UAHash
	row := UARow{Hash: hash}
	if event.Claim != nil {
		sum := sha256.Sum256([]byte("claim\x00" + event.Claim.Name))
		hash = hex.EncodeToString(sum[:])
		row.Hash, row.ClaimedCrawler = hash, &event.Claim.Name
		row.ClaimedCategory, row.ProtectedDefault = &event.Claim.Category, event.Claim.ProtectedDefault
	}
	if id, ok := a.uas[hash]; ok {
		return id, nil
	}
	if event.Claim == nil && a.unclaimedUAs >= a.config.Limits.MaxUserAgents {
		if a.uaOverflowID == 0 {
			a.uaOverflowID = a.nextUAID
			a.nextUAID++
			overflow := UARow{
				ID:       a.uaOverflowID,
				Hash:     "0000000000000000000000000000000000000000000000000000000000000000",
				Overflow: true,
			}
			a.uaRows[overflow.ID] = overflow
			a.newUAs = append(a.newUAs, overflow)
		}
		if err := increment(&a.summary.UAOverflow); err != nil {
			return 0, err
		}
		return a.uaOverflowID, nil
	}
	id := a.nextUAID
	a.nextUAID++
	row.ID = id
	a.uas[hash], a.uaRows[id] = id, row
	a.newUAs = append(a.newUAs, row)
	if event.Claim == nil {
		a.unclaimedUAs++
	}
	return id, nil
}

func addCell(cell *CellRow, event domain.Event) error {
	var err error
	if cell.Requests, err = checkedAdd(cell.Requests, 1); err != nil {
		return err
	}
	if cell.BytesSent, err = checkedAdd(cell.BytesSent, event.BytesSent); err != nil {
		return err
	}
	if event.RequestDurationUS != nil {
		if cell.RequestDurationUS, err = addNullable(cell.RequestDurationUS, *event.RequestDurationUS); err != nil {
			return err
		}
		if err := increment(&cell.RequestSamples); err != nil {
			return err
		}
	}
	if event.UpstreamDurationUS != nil {
		if cell.UpstreamDurationUS, err = addNullable(cell.UpstreamDurationUS, *event.UpstreamDurationUS); err != nil {
			return err
		}
		if err := increment(&cell.UpstreamSamples); err != nil {
			return err
		}
	}
	if event.RefererHost != nil {
		if err := increment(&cell.RefererPresent); err != nil {
			return err
		}
	}
	return nil
}

func (a *Aggregator) addRoute(routeID int64, event domain.Event) error {
	stats := a.routeStats[routeID]
	if stats == nil {
		stats = &routeAccumulator{row: RouteStatsRow{RouteID: routeID}}
		a.routeStats[routeID] = stats
	}
	var err error
	stats.row.Requests, err = checkedAdd(stats.row.Requests, 1)
	if err != nil {
		return err
	}
	stats.row.BytesSent, err = checkedAdd(stats.row.BytesSent, event.BytesSent)
	if err != nil {
		return err
	}
	if event.QueryFingerprint != nil {
		if err := increment(&stats.row.QueryRequests); err != nil {
			return err
		}
		stats.queries.Add(*event.QueryFingerprint)
	}
	if event.Status == 404 {
		if err := increment(&stats.row.Status404); err != nil {
			return err
		}
	}
	if event.Method == "GET" || event.Method == "HEAD" {
		if event.CacheState != domain.CacheUnknown {
			if err := increment(&stats.row.CacheSamples); err != nil {
				return err
			}
		}
		if event.CacheState == domain.CacheMiss || event.CacheState == domain.CacheBypass || event.CacheState == domain.CacheExpired {
			if err := increment(&stats.row.CacheMisses); err != nil {
				return err
			}
		}
	}
	if event.UpstreamDurationUS != nil {
		stats.row.UpstreamDurationUS, err = addNullable(stats.row.UpstreamDurationUS, *event.UpstreamDurationUS)
		if err != nil {
			return err
		}
		if err := increment(&stats.row.UpstreamSamples); err != nil {
			return err
		}
	}
	stats.clients.Add(event.ClientKey)
	stats.urls.Add(event.URLFingerprint)
	return nil
}

func (a *Aggregator) addSubject(uaID int64, event domain.Event) error {
	key := subjectKey{client: event.ClientKey, uaID: uaID}
	subject := a.subjects[key]
	if subject == nil {
		if _, tracked := a.rateSubjects[key]; !tracked &&
			len(a.rateSubjects) >= a.config.Limits.MaxRateSubjects {
			return increment(&a.summary.SubjectOverflow)
		}
		subject = &subjectAccumulator{row: SubjectRow{
			ClientKey: event.ClientKey, UAID: uaID, Claimed: event.Claim != nil,
			FirstSeenUS: event.TimestampUS, LastSeenUS: event.TimestampUS,
		}}
		a.subjects[key] = subject
	}
	if err := increment(&subject.row.Requests); err != nil {
		return err
	}
	if event.Status >= 400 && event.Status <= 499 {
		if err := increment(&subject.row.Status4xx); err != nil {
			return err
		}
	}
	if event.RefererHost == nil {
		if err := increment(&subject.row.NoReferer); err != nil {
			return err
		}
	}
	if len(event.SecurityProbeIDs) > 0 {
		if err := increment(&subject.row.ProbeRequests); err != nil {
			return err
		}
	}
	if event.RobotsAllowed != nil && !*event.RobotsAllowed {
		if err := increment(&subject.row.RobotsViolations); err != nil {
			return err
		}
	}
	subject.routes.Add(event.Route)
	if event.TimestampUS < subject.row.FirstSeenUS {
		subject.row.FirstSeenUS = event.TimestampUS
	}
	if event.TimestampUS > subject.row.LastSeenUS {
		subject.row.LastSeenUS = event.TimestampUS
	}
	return nil
}

func (a *Aggregator) addRate(uaID int64, event domain.Event) error {
	key := subjectKey{client: event.ClientKey, uaID: uaID}
	state := a.rateSubjects[key]
	if state == nil {
		if len(a.rateSubjects) >= a.config.Limits.MaxRateSubjects {
			return nil
		}
		state = &rateSubject{}
		a.rateSubjects[key] = state
	}
	for index, profile := range Profiles {
		allowed, err := state.buckets[index].allow(event.TimestampUS, profile)
		if err != nil {
			return err
		}
		if state.buckets[index].unordered {
			a.summary.OrderDegraded = true
			continue
		}
		impactKey := rateImpactKey{uaID: uaID, class: event.PrimaryClass, profile: profile.Name}
		impact := a.rateImpacts[impactKey]
		if impact == nil {
			impact = &RateImpactRow{UAID: uaID, PrimaryClass: event.PrimaryClass, Profile: profile.Name}
			a.rateImpacts[impactKey] = impact
		}
		if err := addRateImpact(impact, event, allowed); err != nil {
			return err
		}
		if index == 0 {
			if err := increment(&a.summary.RateModeled); err != nil {
				return err
			}
		}
	}
	return nil
}

func (a *Aggregator) addSummary(event domain.Event) error {
	var err error
	a.summary.Accepted, err = checkedAdd(a.summary.Accepted, 1)
	if err != nil {
		return err
	}
	a.summary.BytesSent, err = checkedAdd(a.summary.BytesSent, event.BytesSent)
	if err != nil {
		return err
	}
	if event.RequestDurationUS != nil {
		a.summary.RequestDurationUS, err = addNullable(a.summary.RequestDurationUS, *event.RequestDurationUS)
		if err != nil {
			return err
		}
		if err := increment(&a.summary.RequestDurationSamples); err != nil {
			return err
		}
	}
	if event.UpstreamDurationUS != nil {
		a.summary.UpstreamDurationUS, err = addNullable(a.summary.UpstreamDurationUS, *event.UpstreamDurationUS)
		if err != nil {
			return err
		}
		if err := increment(&a.summary.UpstreamDurationSamples); err != nil {
			return err
		}
	}
	if event.CacheState != domain.CacheUnknown {
		if err := increment(&a.summary.CacheSamples); err != nil {
			return err
		}
	}
	if event.RefererHost != nil {
		if err := increment(&a.summary.RefererSamples); err != nil {
			return err
		}
	}
	if event.RobotsAllowed != nil {
		if err := increment(&a.summary.RobotsChecked); err != nil {
			return err
		}
	}
	if a.summary.FirstEventUS == nil || event.TimestampUS < *a.summary.FirstEventUS {
		value := event.TimestampUS
		a.summary.FirstEventUS = &value
	}
	if a.summary.LastEventUS == nil || event.TimestampUS > *a.summary.LastEventUS {
		value := event.TimestampUS
		a.summary.LastEventUS = &value
	}
	return nil
}

func (a *Aggregator) batchFull() bool {
	return len(a.newUAs)+len(a.newRoutes)+len(a.cells)+len(a.routeStats)+len(a.subjects)+
		len(a.rateImpacts)+len(a.robots)+len(a.queryKeys)+len(a.probes) >= a.config.Limits.MaxBatchCells
}

func (a *Aggregator) flush(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	batch := Batch{UserAgents: append([]UARow(nil), a.newUAs...), Routes: append([]RouteRow(nil), a.newRoutes...)}
	for _, cell := range a.cells {
		batch.Cells = append(batch.Cells, *cell)
	}
	for _, stats := range a.routeStats {
		stats.row.DistinctClientsKMV, _ = stats.clients.MarshalBinary()
		stats.row.DistinctURLsKMV, _ = stats.urls.MarshalBinary()
		stats.row.DistinctQueriesKMV, _ = stats.queries.MarshalBinary()
		batch.RouteStats = append(batch.RouteStats, stats.row)
	}
	for _, subject := range a.subjects {
		subject.row.DistinctRoutesKMV, _ = subject.routes.MarshalBinary()
		batch.Subjects = append(batch.Subjects, subject.row)
	}
	for _, impact := range a.rateImpacts {
		batch.RateImpacts = append(batch.RateImpacts, *impact)
	}
	for key, requests := range a.robots {
		batch.RobotsViolations = append(batch.RobotsViolations, RobotsRow{UAID: key[0], RouteID: key[1], Requests: requests})
	}
	for key, requests := range a.queryKeys {
		batch.QueryKeys = append(batch.QueryKeys, QueryKeyRow{RouteID: key.routeID, Key: key.key, Requests: requests})
	}
	for key, requests := range a.probes {
		batch.ProbeHits = append(batch.ProbeHits, ProbeRow{ProbeID: key.id, RouteID: key.routeID, Requests: requests})
	}
	sortBatch(&batch)
	if batch.Empty() {
		return nil
	}
	if err := a.sink.Flush(ctx, batch); err != nil {
		return err
	}
	a.newUAs, a.newRoutes = nil, nil
	a.cells = make(map[cellKey]*CellRow)
	a.routeStats = make(map[int64]*routeAccumulator)
	a.subjects = make(map[subjectKey]*subjectAccumulator)
	a.rateImpacts = make(map[rateImpactKey]*RateImpactRow)
	a.robots = make(map[[2]int64]int64)
	a.queryKeys = make(map[queryKey]int64)
	a.probes = make(map[probeKey]int64)
	return nil
}

func sortBatch(batch *Batch) {
	sort.Slice(batch.UserAgents, func(i, j int) bool { return batch.UserAgents[i].ID < batch.UserAgents[j].ID })
	sort.Slice(batch.Routes, func(i, j int) bool { return batch.Routes[i].ID < batch.Routes[j].ID })
	sort.Slice(batch.Cells, func(i, j int) bool {
		a, b := batch.Cells[i], batch.Cells[j]
		if a.BucketMinuteUS != b.BucketMinuteUS {
			return a.BucketMinuteUS < b.BucketMinuteUS
		}
		if a.RouteID != b.RouteID {
			return a.RouteID < b.RouteID
		}
		if a.UAID != b.UAID {
			return a.UAID < b.UAID
		}
		if a.PrimaryClass != b.PrimaryClass {
			return a.PrimaryClass < b.PrimaryClass
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		if a.Status != b.Status {
			return a.Status < b.Status
		}
		return a.CacheState < b.CacheState
	})
	sort.Slice(batch.RouteStats, func(i, j int) bool { return batch.RouteStats[i].RouteID < batch.RouteStats[j].RouteID })
	sort.Slice(batch.Subjects, func(i, j int) bool {
		if batch.Subjects[i].ClientKey != batch.Subjects[j].ClientKey {
			return batch.Subjects[i].ClientKey < batch.Subjects[j].ClientKey
		}
		return batch.Subjects[i].UAID < batch.Subjects[j].UAID
	})
	sort.Slice(batch.RateImpacts, func(i, j int) bool {
		a, b := batch.RateImpacts[i], batch.RateImpacts[j]
		if a.UAID != b.UAID {
			return a.UAID < b.UAID
		}
		if a.PrimaryClass != b.PrimaryClass {
			return a.PrimaryClass < b.PrimaryClass
		}
		return a.Profile < b.Profile
	})
	sort.Slice(batch.RobotsViolations, func(i, j int) bool {
		if batch.RobotsViolations[i].UAID != batch.RobotsViolations[j].UAID {
			return batch.RobotsViolations[i].UAID < batch.RobotsViolations[j].UAID
		}
		return batch.RobotsViolations[i].RouteID < batch.RobotsViolations[j].RouteID
	})
	sort.Slice(batch.QueryKeys, func(i, j int) bool {
		if batch.QueryKeys[i].RouteID != batch.QueryKeys[j].RouteID {
			return batch.QueryKeys[i].RouteID < batch.QueryKeys[j].RouteID
		}
		return batch.QueryKeys[i].Key < batch.QueryKeys[j].Key
	})
	sort.Slice(batch.ProbeHits, func(i, j int) bool {
		if batch.ProbeHits[i].ProbeID != batch.ProbeHits[j].ProbeID {
			return batch.ProbeHits[i].ProbeID < batch.ProbeHits[j].ProbeID
		}
		return batch.ProbeHits[i].RouteID < batch.ProbeHits[j].RouteID
	})
}

func checkedAdd(left, right int64) (int64, error) {
	if right > 0 && left > math.MaxInt64-right || right < 0 && left < math.MinInt64-right {
		return 0, errors.New("integer overflow")
	}
	return left + right, nil
}

func increment(value *int64) error {
	result, err := checkedAdd(*value, 1)
	if err == nil {
		*value = result
	}
	return err
}

func addNullable(value *int64, add int64) (*int64, error) {
	if value == nil {
		result := add
		return &result, nil
	}
	result, err := checkedAdd(*value, add)
	return &result, err
}
