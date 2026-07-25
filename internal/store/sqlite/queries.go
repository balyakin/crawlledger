package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/balyakin/crawlledger/internal/aggregate"
	"github.com/balyakin/crawlledger/internal/domain"
)

func (s *Store) LoadReportData(ctx context.Context) (domain.ReportData, error) {
	var data domain.ReportData
	var finished, first, last sql.NullInt64
	err := s.database.QueryRowContext(ctx, `
		SELECT id, schema_version, tool_version, status, started_at_us, finished_at_us,
			first_event_at_us, last_event_at_us, input_format, catalog_version, key_id,
			config_json, total_lines, accepted_lines, rejected_lines, skipped_lines,
			total_bytes, request_duration_us, upstream_duration_us, rate_model_requests,
			route_overflow_requests, ua_overflow_requests
		FROM analyses WHERE id=?`, s.analysisID).Scan(
		&data.Analysis.ID, &data.Analysis.SchemaVersion, &data.Analysis.ToolVersion,
		&data.Analysis.Status, &data.Analysis.StartedAtUS, &finished, &first, &last,
		&data.Analysis.InputFormat, &data.Analysis.CatalogVersion, &data.Analysis.KeyID,
		&data.Analysis.ConfigJSON, &data.Summary.TotalLines, &data.Summary.Accepted,
		&data.Summary.Rejected, &data.Summary.Skipped, &data.Summary.BytesSent,
		&data.Summary.RequestDurationUS, &data.Summary.UpstreamDurationUS,
		&data.Summary.RateModeled, &data.Summary.RouteOverflow, &data.Summary.UAOverflow,
	)
	if err != nil {
		return data, err
	}
	data.Summary.AnalysisID = s.analysisID
	data.Analysis.FinishedAtUS = nullable(finished)
	data.Analysis.FirstEventUS, data.Analysis.LastEventUS = nullable(first), nullable(last)
	data.Summary.FirstEventUS, data.Summary.LastEventUS = nullable(first), nullable(last)
	if err := s.loadCoverage(ctx, &data); err != nil {
		return data, err
	}
	if data.Classes, err = s.loadClasses(ctx); err != nil {
		return data, err
	}
	if data.Crawlers, err = s.loadCrawlers(ctx); err != nil {
		return data, err
	}
	if data.Routes, err = s.loadRoutes(ctx); err != nil {
		return data, err
	}
	if data.Subjects, err = s.loadSubjects(ctx); err != nil {
		return data, err
	}
	if data.Robots, err = s.loadRobotsViolations(ctx); err != nil {
		return data, err
	}
	if data.Probes, err = s.loadProbeHits(ctx); err != nil {
		return data, err
	}
	if data.Findings, err = s.loadFindings(ctx); err != nil {
		return data, err
	}
	return data, nil
}

func (s *Store) loadRobotsViolations(ctx context.Context) ([]domain.RobotsViolationStats, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT ua.claimed_crawler, r.normalized_path, sum(v.requests)
		FROM robots_violations v
		JOIN user_agents ua ON ua.id=v.user_agent_id
		JOIN routes r ON r.id=v.route_id
		WHERE v.analysis_id=? AND ua.claimed_crawler IS NOT NULL
		GROUP BY ua.claimed_crawler, r.normalized_path
		ORDER BY ua.claimed_crawler, r.normalized_path`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.RobotsViolationStats, 0)
	for rows.Next() {
		var row domain.RobotsViolationStats
		if err := rows.Scan(&row.Crawler, &row.Route, &row.Requests); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) loadProbeHits(ctx context.Context) ([]domain.ProbeHitStats, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT p.probe_id, coalesce(r.actionable_prefix, r.normalized_path), sum(p.requests)
		FROM probe_hits p JOIN routes r ON r.id=p.route_id
		WHERE p.analysis_id=?
		GROUP BY p.probe_id, coalesce(r.actionable_prefix, r.normalized_path)
		ORDER BY p.probe_id, coalesce(r.actionable_prefix, r.normalized_path)`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.ProbeHitStats, 0)
	for rows.Next() {
		var row domain.ProbeHitStats
		if err := rows.Scan(&row.ProbeID, &row.Route, &row.Requests); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) loadCoverage(ctx context.Context, data *domain.ReportData) error {
	return s.database.QueryRowContext(ctx, `
		SELECT coalesce(sum(request_duration_samples),0),
			coalesce(sum(upstream_duration_samples),0),
			coalesce(sum(CASE WHEN cache_state <> 'unknown' THEN requests ELSE 0 END),0),
			coalesce(sum(referer_present),0)
		FROM traffic_cells WHERE analysis_id=?`, s.analysisID).Scan(
		&data.Summary.RequestDurationSamples, &data.Summary.UpstreamDurationSamples,
		&data.Summary.CacheSamples, &data.Summary.RefererSamples,
	)
}

func (s *Store) loadClasses(ctx context.Context) ([]domain.ClassStats, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT primary_class, sum(requests), sum(bytes_sent),
			CASE WHEN sum(upstream_duration_samples)=0 THEN NULL ELSE sum(upstream_duration_us) END
		FROM traffic_cells WHERE analysis_id=? GROUP BY primary_class
		ORDER BY sum(requests) DESC, primary_class`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.ClassStats, 0)
	for rows.Next() {
		var row domain.ClassStats
		if err := rows.Scan(&row.Class, &row.Requests, &row.BytesSent, &row.UpstreamDurationUS); err != nil {
			return nil, err
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) loadCrawlers(ctx context.Context) ([]domain.CrawlerStats, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT ua.claimed_crawler, ua.claimed_category, ua.protected_default,
			sum(c.requests), sum(c.bytes_sent),
			CASE WHEN sum(c.upstream_duration_samples)=0 THEN NULL ELSE sum(c.upstream_duration_us) END
		FROM traffic_cells c JOIN user_agents ua ON ua.id=c.user_agent_id
		WHERE c.analysis_id=? AND ua.claimed_crawler IS NOT NULL
		GROUP BY ua.id ORDER BY
			CASE WHEN sum(c.upstream_duration_samples)=0 THEN 1 ELSE 0 END,
			sum(c.upstream_duration_us) DESC, sum(c.requests) DESC, ua.claimed_crawler
		LIMIT 100`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.CrawlerStats, 0)
	for rows.Next() {
		var row domain.CrawlerStats
		var protected int
		if err := rows.Scan(&row.Name, &row.Category, &protected, &row.Requests, &row.BytesSent, &row.UpstreamDurationUS); err != nil {
			return nil, err
		}
		row.ProtectedDefault = protected == 1
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) loadRoutes(ctx context.Context) ([]domain.RouteStats, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT r.id, r.normalized_path, r.actionable_prefix, r.is_overflow,
			rs.requests, rs.query_requests, rs.status_404, rs.cache_misses, rs.bytes_sent,
			rs.upstream_duration_us, rs.distinct_clients_kmv, rs.distinct_urls_kmv,
			rs.distinct_queries_kmv,
			coalesce((SELECT sum(requests) FROM traffic_cells c WHERE c.analysis_id=r.analysis_id
				AND c.route_id=r.id AND c.method IN ('GET','HEAD')
				AND c.cache_state <> 'unknown'),0),
			coalesce((SELECT sum(requests) FROM traffic_cells c WHERE c.analysis_id=r.analysis_id
				AND c.route_id=r.id AND c.method IN ('GET','HEAD')),0),
			coalesce((SELECT sum(upstream_duration_samples) FROM traffic_cells c
				WHERE c.analysis_id=r.analysis_id AND c.route_id=r.id),0),
			q.top_query_keys
		FROM routes r JOIN route_stats rs ON rs.analysis_id=r.analysis_id AND rs.route_id=r.id
		LEFT JOIN (
			SELECT normalized_path, json_group_array(query_key) AS top_query_keys
			FROM (
				SELECT normalized_path, query_key, rank FROM (
					SELECT normalized_path, query_key,
						row_number() OVER (
							PARTITION BY normalized_path ORDER BY requests DESC, query_key
						) AS rank
					FROM (
						SELECT r.normalized_path, q.query_key, sum(q.requests) AS requests
						FROM route_query_keys q
						JOIN routes r ON r.analysis_id=q.analysis_id AND r.id=q.route_id
						WHERE q.analysis_id=?
						GROUP BY r.normalized_path, q.query_key
					)
				) WHERE rank<=20 ORDER BY normalized_path, rank
			) GROUP BY normalized_path
		) q ON q.normalized_path=r.normalized_path
		WHERE r.analysis_id=? ORDER BY rs.requests DESC, r.normalized_path, r.id`,
		s.analysisID, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type routeAccumulator struct {
		row                    domain.RouteStats
		clients, urls, queries aggregate.Sketch
	}
	combined := make(map[string]*routeAccumulator)
	for rows.Next() {
		var row domain.RouteStats
		var overflow int
		var clients, urls, queries []byte
		var topKeys sql.NullString
		if err := rows.Scan(
			&row.ID, &row.Route, &row.ActionablePrefix, &overflow, &row.Requests,
			&row.QueryRequests, &row.Status404, &row.CacheMisses, &row.BytesSent,
			&row.UpstreamDurationUS, &clients, &urls, &queries, &row.CacheSamples,
			&row.CacheEligible, &row.UpstreamSamples, &topKeys,
		); err != nil {
			return nil, err
		}
		row.Overflow = overflow == 1
		var clientSketch, urlSketch, querySketch aggregate.Sketch
		if err := clientSketch.UnmarshalBinary(clients); err != nil {
			return nil, err
		}
		if err := urlSketch.UnmarshalBinary(urls); err != nil {
			return nil, err
		}
		if err := querySketch.UnmarshalBinary(queries); err != nil {
			return nil, err
		}
		row.TopQueryKeys = []string{}
		if topKeys.Valid {
			if err := json.Unmarshal([]byte(topKeys.String), &row.TopQueryKeys); err != nil {
				return nil, err
			}
		}
		target := combined[row.Route]
		if target == nil {
			target = &routeAccumulator{row: row}
			combined[row.Route] = target
		} else {
			if target.row.ActionablePrefix == nil || row.ActionablePrefix == nil ||
				*target.row.ActionablePrefix != *row.ActionablePrefix {
				target.row.ActionablePrefix = nil
			}
			target.row.Overflow = target.row.Overflow || row.Overflow
			for _, pair := range [][2]*int64{
				{&target.row.Requests, &row.Requests},
				{&target.row.QueryRequests, &row.QueryRequests},
				{&target.row.Status404, &row.Status404},
				{&target.row.CacheMisses, &row.CacheMisses},
				{&target.row.CacheSamples, &row.CacheSamples},
				{&target.row.CacheEligible, &row.CacheEligible},
				{&target.row.BytesSent, &row.BytesSent},
				{&target.row.UpstreamSamples, &row.UpstreamSamples},
			} {
				if err := addInt64(pair[0], *pair[1]); err != nil {
					return nil, err
				}
			}
			if err := addNullableInt64(&target.row.UpstreamDurationUS, row.UpstreamDurationUS); err != nil {
				return nil, err
			}
		}
		target.clients.Merge(clientSketch)
		target.urls.Merge(urlSketch)
		target.queries.Merge(querySketch)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	routes := make([]string, 0, len(combined))
	for route := range combined {
		routes = append(routes, route)
	}
	sort.Strings(routes)
	result := make([]domain.RouteStats, 0, len(routes))
	for _, route := range routes {
		target := combined[route]
		target.row.DistinctClients = target.clients.Conservative(target.row.Requests)
		target.row.DistinctURLs = target.urls.Conservative(target.row.Requests)
		target.row.DistinctQueries = target.queries.Conservative(target.row.QueryRequests)
		target.row.DistinctApproximate = target.clients.Approximate() ||
			target.urls.Approximate() || target.queries.Approximate()
		result = append(result, target.row)
	}
	return result, nil
}

func addInt64(target *int64, value int64) error {
	if value < 0 || *target > math.MaxInt64-value {
		return fmt.Errorf("route aggregate integer overflow")
	}
	*target += value
	return nil
}

func addNullableInt64(target **int64, value *int64) error {
	if value == nil {
		return nil
	}
	if *target == nil {
		copy := *value
		*target = &copy
		return nil
	}
	return addInt64(*target, *value)
}

func (s *Store) loadSubjects(ctx context.Context) ([]domain.SubjectStats, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT ss.client_key, CASE WHEN ua.claimed_crawler IS NULL THEN 0 ELSE 1 END,
			ss.requests, ss.status_4xx, ss.no_referer, ss.probe_requests,
			ss.robots_violations, ss.distinct_routes_kmv, ss.first_seen_us, ss.last_seen_us
		FROM subject_stats ss JOIN user_agents ua ON ua.id=ss.user_agent_id
		WHERE ss.analysis_id=? ORDER BY ss.client_key, ss.user_agent_id`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.SubjectStats, 0)
	for rows.Next() {
		var row domain.SubjectStats
		var claimed int
		var sketchBytes []byte
		if err := rows.Scan(
			&row.ClientKey, &claimed, &row.Requests, &row.Status4xx, &row.NoReferer,
			&row.ProbeRequests, &row.RobotsViolations, &sketchBytes,
			&row.FirstSeenUS, &row.LastSeenUS,
		); err != nil {
			return nil, err
		}
		row.Claimed = claimed == 1
		var sketch aggregate.Sketch
		if err := sketch.UnmarshalBinary(sketchBytes); err != nil {
			return nil, err
		}
		row.DistinctRoutes = sketch.Conservative(row.Requests)
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) loadFindings(ctx context.Context) ([]domain.Finding, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT f.id, f.kind, f.severity, f.title, f.summary, r.normalized_path,
			f.subject_key, f.evidence_json, f.recommended_action, f.confidence
		FROM findings f LEFT JOIN routes r ON r.id=f.route_id
		WHERE f.analysis_id=? ORDER BY
			CASE f.severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3
				WHEN 'low' THEN 2 ELSE 1 END DESC,
			f.kind, coalesce(r.normalized_path,''), coalesce(f.subject_key,'')`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.Finding, 0)
	for rows.Next() {
		var row domain.Finding
		var route, subject sql.NullString
		var evidence string
		if err := rows.Scan(
			&row.ID, &row.Kind, &row.Severity, &row.Title, &row.Summary, &route,
			&subject, &evidence, &row.RecommendedAction, &row.Confidence,
		); err != nil {
			return nil, err
		}
		row.Route, row.Subject = nullableString(route), nullableString(subject)
		if err := json.Unmarshal([]byte(evidence), &row.Evidence); err != nil {
			return nil, err
		}
		if row.Evidence == nil {
			row.Evidence = []domain.Evidence{}
		}
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) VisitTrafficCells(ctx context.Context, visit func(domain.TrafficCell) error) error {
	rows, err := s.database.QueryContext(ctx, `
		SELECT r.normalized_path, r.actionable_prefix, c.method, ua.claimed_crawler,
			ua.claimed_category, ua.protected_default, c.primary_class, c.status_code,
			c.cache_state, c.requests, c.bytes_sent, c.upstream_duration_us,
			c.upstream_duration_samples
		FROM traffic_cells c
		JOIN routes r ON r.id=c.route_id
		JOIN user_agents ua ON ua.id=c.user_agent_id
		WHERE c.analysis_id=?
		ORDER BY r.normalized_path, r.id, c.bucket_minute_us, c.user_agent_id,
			c.primary_class, c.method, c.status_code, c.cache_state`, s.analysisID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cell domain.TrafficCell
		var claimName, claimCategory sql.NullString
		var protected int
		if err := rows.Scan(
			&cell.Route, &cell.ActionablePrefix, &cell.Method, &claimName, &claimCategory,
			&protected, &cell.PrimaryClass, &cell.Status, &cell.CacheState, &cell.Requests,
			&cell.BytesSent, &cell.UpstreamUS, &cell.UpstreamSamples,
		); err != nil {
			return err
		}
		cell.ProtectedDefault = protected == 1
		if claimName.Valid {
			cell.ClaimName = &claimName.String
			category := domain.TrafficClass(claimCategory.String)
			cell.ClaimCategory = &category
		}
		if err := visit(cell); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) LoadRateImpacts(ctx context.Context) ([]domain.RateProfileImpact, error) {
	rows, err := s.database.QueryContext(ctx, `
		SELECT ua.claimed_crawler, ua.claimed_category, ua.protected_default,
			r.primary_class, r.profile, r.modeled_requests, r.allowed_requests,
			r.limited_requests, r.allowed_bytes, r.limited_bytes,
			r.limited_upstream_us, r.limited_upstream_samples
		FROM rate_profile_impacts r
		JOIN user_agents ua ON ua.id=r.user_agent_id
		WHERE r.analysis_id=?
		ORDER BY ua.claimed_crawler, r.primary_class, r.profile`, s.analysisID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]domain.RateProfileImpact, 0)
	for rows.Next() {
		var row domain.RateProfileImpact
		var name, category sql.NullString
		var protected int
		if err := rows.Scan(
			&name, &category, &protected, &row.PrimaryClass, &row.Profile,
			&row.ModeledRequests, &row.AllowedRequests, &row.LimitedRequests,
			&row.AllowedBytes, &row.LimitedBytes, &row.LimitedUpstreamUS,
			&row.LimitedUpstreamSamples,
		); err != nil {
			return nil, err
		}
		row.ClaimName = nullableString(name)
		if category.Valid {
			value := domain.TrafficClass(category.String)
			row.ClaimCategory = &value
		}
		row.ProtectedDefault = protected == 1
		result = append(result, row)
	}
	return result, rows.Err()
}

func (s *Store) VisitSubjectStates(
	ctx context.Context,
	visit func(claimName *string, claimCategory *domain.TrafficClass) error,
) error {
	rows, err := s.database.QueryContext(ctx, `
		SELECT ua.claimed_crawler, ua.claimed_category
		FROM subject_stats ss
		JOIN user_agents ua ON ua.id=ss.user_agent_id
		WHERE ss.analysis_id=?
		ORDER BY ss.client_key, ss.user_agent_id`, s.analysisID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, category sql.NullString
		if err := rows.Scan(&name, &category); err != nil {
			return err
		}
		var categoryValue *domain.TrafficClass
		if category.Valid {
			value := domain.TrafficClass(category.String)
			categoryValue = &value
		}
		if err := visit(nullableString(name), categoryValue); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Store) VerifyCompleted(ctx context.Context, analysisID, catalogVersion string) error {
	var count, schemaVersion int
	var id, status, catalog string
	if err := s.database.QueryRowContext(ctx, `
		SELECT count(*), coalesce(min(id),''), coalesce(min(schema_version),0),
			coalesce(min(status),''), coalesce(min(catalog_version),'')
		FROM analyses`).Scan(&count, &id, &schemaVersion, &status, &catalog); err != nil {
		return err
	}
	if count != 1 || id != analysisID || schemaVersion != 1 || status != "completed" ||
		catalog != catalogVersion {
		return errors.New("workspace analysis contract mismatch")
	}
	var userVersion, migrations int
	if err := s.database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&userVersion); err != nil {
		return err
	}
	if err := s.database.QueryRowContext(ctx,
		"SELECT count(*) FROM schema_migrations WHERE version=1").Scan(&migrations); err != nil {
		return err
	}
	if userVersion != 1 || migrations != 1 {
		return errors.New("unsupported workspace schema")
	}
	return nil
}

func (s *Store) LoadCostMetadata(ctx context.Context) (domain.CostMetadata, error) {
	var result domain.CostMetadata
	var first, last, upstream sql.NullInt64
	err := s.database.QueryRowContext(ctx, `
		SELECT first_event_at_us, last_event_at_us, accepted_lines, total_bytes,
			upstream_duration_us,
			coalesce((SELECT sum(upstream_duration_samples) FROM traffic_cells
				WHERE analysis_id=?),0),
			config_json
		FROM analyses WHERE id=?`, s.analysisID, s.analysisID).Scan(
		&first, &last, &result.Accepted, &result.BytesSent, &upstream,
		&result.UpstreamDurationSamples, &result.ConfigJSON,
	)
	result.FirstEventUS, result.LastEventUS, result.UpstreamUS = nullable(first), nullable(last), nullable(upstream)
	return result, err
}

func (s *Store) LoadOverflowCounts(ctx context.Context) (routes, userAgents, subjects int64, err error) {
	err = s.database.QueryRowContext(ctx, `
		SELECT route_overflow_requests, ua_overflow_requests, 0
		FROM analyses WHERE id=?`, s.analysisID).Scan(&routes, &userAgents, &subjects)
	return
}

func nullable(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	return &value.Int64
}

func nullableString(value sql.NullString) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}
