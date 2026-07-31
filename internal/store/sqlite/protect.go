package sqlite

import (
	"context"
	"errors"
	"fmt"

	"github.com/balyakin/crawlledger/internal/domain"
)

type ProtectionHistory = domain.ProtectionHistory
type ProtectionCell = domain.ProtectionCell

func (s *Store) LoadProtectionHistory(ctx context.Context) (ProtectionHistory, error) {
	if s.analysisID == "" {
		return ProtectionHistory{}, errors.New("analysis ID is not set")
	}
	history := ProtectionHistory{Cells: []ProtectionCell{}}
	err := s.database.QueryRowContext(ctx, `
		SELECT input_format, first_event_at_us, last_event_at_us, route_overflow_requests
		FROM analyses WHERE id=? AND status='completed'`, s.analysisID,
	).Scan(
		&history.InputFormat,
		&history.FirstEventUS,
		&history.LastEventUS,
		&history.RouteOverflowRequests,
	)
	if err != nil {
		return ProtectionHistory{}, fmt.Errorf("load protection analysis: %w", err)
	}
	rows, err := s.database.QueryContext(ctx, `
		SELECT
			cells.bucket_minute_us,
			routes.normalized_path,
			routes.actionable_prefix,
			routes.is_overflow,
			cells.method,
			sum(cells.requests),
			coalesce(sum(cells.upstream_duration_us), 0),
			sum(cells.upstream_duration_samples)
		FROM traffic_cells AS cells
		JOIN routes ON routes.id=cells.route_id AND routes.analysis_id=cells.analysis_id
		WHERE cells.analysis_id=? AND cells.status_code NOT IN (403, 429)
		GROUP BY
			cells.bucket_minute_us,
			routes.normalized_path,
			routes.actionable_prefix,
			routes.is_overflow,
			cells.method
		ORDER BY cells.bucket_minute_us, cells.method, routes.normalized_path, routes.actionable_prefix`,
		s.analysisID,
	)
	if err != nil {
		return ProtectionHistory{}, fmt.Errorf("query protection cells: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var cell ProtectionCell
		var overflow int
		if err := rows.Scan(
			&cell.BucketMinuteUS,
			&cell.Route,
			&cell.ActionablePrefix,
			&overflow,
			&cell.Method,
			&cell.Requests,
			&cell.UpstreamDurationUS,
			&cell.UpstreamSamples,
		); err != nil {
			return ProtectionHistory{}, fmt.Errorf("scan protection cell: %w", err)
		}
		cell.RouteOverflow = overflow != 0
		history.Cells = append(history.Cells, cell)
	}
	if err := rows.Err(); err != nil {
		return ProtectionHistory{}, fmt.Errorf("iterate protection cells: %w", err)
	}
	return history, nil
}
