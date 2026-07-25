package sqlite

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"time"

	"github.com/balyakin/crawlledger/internal/aggregate"
	modernsqlite "modernc.org/sqlite"
)

func init() {
	modernsqlite.MustRegisterDeterministicScalarFunction(
		"crawlledger_kmv_merge",
		2,
		func(_ *modernsqlite.FunctionContext, values []driver.Value) (driver.Value, error) {
			if len(values) != 2 {
				return nil, errors.New("KMV merge requires two values")
			}
			left, leftOK := values[0].([]byte)
			right, rightOK := values[1].([]byte)
			if !leftOK || !rightOK {
				return nil, errors.New("KMV merge requires blobs")
			}
			var merged, delta aggregate.Sketch
			if err := merged.UnmarshalBinary(left); err != nil {
				return nil, err
			}
			if err := delta.UnmarshalBinary(right); err != nil {
				return nil, err
			}
			merged.Merge(delta)
			return merged.MarshalBinary()
		},
	)
}

func (s *Store) Flush(ctx context.Context, batch aggregate.Batch) error {
	if s.analysisID == "" {
		return errors.New("analysis ID is not set")
	}
	transactionContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	transaction, err := s.database.BeginTx(transactionContext, nil)
	if err != nil {
		return err
	}
	fail := func(cause error) error { return errors.Join(cause, transaction.Rollback()) }
	for _, row := range batch.UserAgents {
		_, err = transaction.ExecContext(transactionContext, `
			INSERT INTO user_agents (
				id, analysis_id, ua_hash, claimed_crawler, claimed_category,
				protected_default, is_overflow
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			row.ID, s.analysisID, row.Hash, row.ClaimedCrawler, row.ClaimedCategory,
			boolInt(row.ProtectedDefault), boolInt(row.Overflow),
		)
		if err != nil {
			return fail(err)
		}
	}
	for _, row := range batch.Routes {
		_, err = transaction.ExecContext(transactionContext, `
			INSERT INTO routes (id, analysis_id, normalized_path, actionable_prefix, is_overflow)
			VALUES (?, ?, ?, ?, ?)`,
			row.ID, s.analysisID, row.Route, row.ActionablePrefix, boolInt(row.Overflow),
		)
		if err != nil {
			return fail(err)
		}
	}
	for _, row := range batch.Cells {
		_, err = transaction.ExecContext(transactionContext, `
			INSERT INTO traffic_cells (
				analysis_id, bucket_minute_us, route_id, user_agent_id, primary_class,
				method, status_code, cache_state, requests, bytes_sent,
				request_duration_us, request_duration_samples, upstream_duration_us,
				upstream_duration_samples, referer_present
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET
				requests=requests+excluded.requests,
				bytes_sent=bytes_sent+excluded.bytes_sent,
				request_duration_us=CASE
					WHEN request_duration_us IS NULL THEN excluded.request_duration_us
					WHEN excluded.request_duration_us IS NULL THEN request_duration_us
					ELSE request_duration_us+excluded.request_duration_us END,
				request_duration_samples=request_duration_samples+excluded.request_duration_samples,
				upstream_duration_us=CASE
					WHEN upstream_duration_us IS NULL THEN excluded.upstream_duration_us
					WHEN excluded.upstream_duration_us IS NULL THEN upstream_duration_us
					ELSE upstream_duration_us+excluded.upstream_duration_us END,
				upstream_duration_samples=upstream_duration_samples+excluded.upstream_duration_samples,
				referer_present=referer_present+excluded.referer_present`,
			s.analysisID, row.BucketMinuteUS, row.RouteID, row.UAID, row.PrimaryClass,
			row.Method, row.Status, row.CacheState, row.Requests, row.BytesSent,
			row.RequestDurationUS, row.RequestSamples, row.UpstreamDurationUS,
			row.UpstreamSamples, row.RefererPresent,
		)
		if err != nil {
			return fail(err)
		}
	}
	if err := flushAggregates(transactionContext, transaction, s.analysisID, batch); err != nil {
		return fail(err)
	}
	if err := transaction.Commit(); err != nil {
		return err
	}
	return nil
}

func flushAggregates(ctx context.Context, transaction *sql.Tx, analysisID string, batch aggregate.Batch) error {
	for _, row := range batch.RouteStats {
		_, err := transaction.ExecContext(ctx, `
			INSERT INTO route_stats (
				analysis_id, route_id, requests, query_requests, status_404, cache_misses,
				bytes_sent, upstream_duration_us, distinct_clients_kmv, distinct_urls_kmv,
				distinct_queries_kmv
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET
				requests=requests+excluded.requests,
				query_requests=query_requests+excluded.query_requests,
				status_404=status_404+excluded.status_404,
				cache_misses=cache_misses+excluded.cache_misses,
				bytes_sent=bytes_sent+excluded.bytes_sent,
				upstream_duration_us=CASE
					WHEN upstream_duration_us IS NULL THEN excluded.upstream_duration_us
					WHEN excluded.upstream_duration_us IS NULL THEN upstream_duration_us
					ELSE upstream_duration_us+excluded.upstream_duration_us END,
				distinct_clients_kmv=crawlledger_kmv_merge(distinct_clients_kmv, excluded.distinct_clients_kmv),
				distinct_urls_kmv=crawlledger_kmv_merge(distinct_urls_kmv, excluded.distinct_urls_kmv),
				distinct_queries_kmv=crawlledger_kmv_merge(distinct_queries_kmv, excluded.distinct_queries_kmv)`,
			analysisID, row.RouteID, row.Requests, row.QueryRequests, row.Status404,
			row.CacheMisses, row.BytesSent, row.UpstreamDurationUS, row.DistinctClientsKMV,
			row.DistinctURLsKMV, row.DistinctQueriesKMV,
		)
		if err != nil {
			return err
		}
	}
	for _, row := range batch.Subjects {
		_, err := transaction.ExecContext(ctx, `
			INSERT INTO subject_stats (
				analysis_id, client_key, user_agent_id, requests, status_4xx, no_referer,
				probe_requests, robots_violations, distinct_routes_kmv, first_seen_us, last_seen_us
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET
				requests=requests+excluded.requests,
				status_4xx=status_4xx+excluded.status_4xx,
				no_referer=no_referer+excluded.no_referer,
				probe_requests=probe_requests+excluded.probe_requests,
				robots_violations=robots_violations+excluded.robots_violations,
				distinct_routes_kmv=crawlledger_kmv_merge(distinct_routes_kmv, excluded.distinct_routes_kmv),
				first_seen_us=min(first_seen_us, excluded.first_seen_us),
				last_seen_us=max(last_seen_us, excluded.last_seen_us)`,
			analysisID, row.ClientKey, row.UAID, row.Requests, row.Status4xx, row.NoReferer,
			row.ProbeRequests, row.RobotsViolations, row.DistinctRoutesKMV, row.FirstSeenUS, row.LastSeenUS,
		)
		if err != nil {
			return err
		}
	}
	for _, row := range batch.RateImpacts {
		_, err := transaction.ExecContext(ctx, `
			INSERT INTO rate_profile_impacts (
				analysis_id, user_agent_id, primary_class, profile, modeled_requests,
				allowed_requests, limited_requests, allowed_bytes, limited_bytes,
				limited_upstream_us, limited_upstream_samples
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET
				modeled_requests=modeled_requests+excluded.modeled_requests,
				allowed_requests=allowed_requests+excluded.allowed_requests,
				limited_requests=limited_requests+excluded.limited_requests,
				allowed_bytes=allowed_bytes+excluded.allowed_bytes,
				limited_bytes=limited_bytes+excluded.limited_bytes,
				limited_upstream_us=CASE
					WHEN limited_upstream_us IS NULL THEN excluded.limited_upstream_us
					WHEN excluded.limited_upstream_us IS NULL THEN limited_upstream_us
					ELSE limited_upstream_us+excluded.limited_upstream_us END,
				limited_upstream_samples=limited_upstream_samples+excluded.limited_upstream_samples`,
			analysisID, row.UAID, row.PrimaryClass, row.Profile, row.ModeledRequests,
			row.AllowedRequests, row.LimitedRequests, row.AllowedBytes, row.LimitedBytes,
			row.LimitedUpstreamUS, row.LimitedUpstreamSamples,
		)
		if err != nil {
			return err
		}
	}
	for _, row := range batch.RobotsViolations {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO robots_violations (analysis_id, user_agent_id, route_id, requests)
			VALUES (?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET requests=requests+excluded.requests`,
			analysisID, row.UAID, row.RouteID, row.Requests); err != nil {
			return err
		}
	}
	for _, row := range batch.QueryKeys {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO route_query_keys (analysis_id, route_id, query_key, requests)
			VALUES (?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET requests=requests+excluded.requests`,
			analysisID, row.RouteID, row.Key, row.Requests); err != nil {
			return err
		}
	}
	for _, row := range batch.ProbeHits {
		if _, err := transaction.ExecContext(ctx, `
			INSERT INTO probe_hits (analysis_id, probe_id, route_id, requests)
			VALUES (?, ?, ?, ?)
			ON CONFLICT DO UPDATE SET requests=requests+excluded.requests`,
			analysisID, row.ProbeID, row.RouteID, row.Requests); err != nil {
			return err
		}
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
