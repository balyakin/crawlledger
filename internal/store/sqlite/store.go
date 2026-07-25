package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/balyakin/crawlledger/internal/aggregate"
	"github.com/balyakin/crawlledger/internal/domain"
)

type Store struct {
	database   *sql.DB
	analysisID string
}

func New(database *sql.DB) *Store { return &Store{database: database} }

func NewForAnalysis(database *sql.DB, analysisID string) *Store {
	return &Store{database: database, analysisID: analysisID}
}

func (s *Store) CreateAnalysis(ctx context.Context, row domain.Analysis) error {
	if row.ID == "" || row.Status != "running" {
		return errors.New("invalid running analysis")
	}
	_, err := s.database.ExecContext(ctx, `
		INSERT INTO analyses (
			id, schema_version, tool_version, status, started_at_us, input_format,
			catalog_version, key_id, config_json
		) VALUES (?, ?, ?, 'running', ?, ?, ?, ?, ?)`,
		row.ID, row.SchemaVersion, row.ToolVersion, row.StartedAtUS, row.InputFormat,
		row.CatalogVersion, row.KeyID, row.ConfigJSON,
	)
	if err == nil {
		s.analysisID = row.ID
	}
	return err
}

func (s *Store) CreateSource(ctx context.Context, ordinal int, compression string, compressedBytes *int64) error {
	_, err := s.database.ExecContext(ctx, `
		INSERT INTO source_files (analysis_id, ordinal, compression, compressed_bytes)
		VALUES (?, ?, ?, ?)`, s.analysisID, ordinal, compression, compressedBytes)
	return err
}

func (s *Store) CompleteSource(ctx context.Context, ordinal int, uncompressed int64, digest string, total, accepted, rejected, skipped int64) error {
	if uncompressed < 0 || !conserved(total, accepted, rejected, skipped) {
		return errors.New("source counter conservation failed")
	}
	result, err := s.database.ExecContext(ctx, `
		UPDATE source_files SET uncompressed_bytes=?, content_sha256=?, total_lines=?,
			accepted_lines=?, rejected_lines=?, skipped_lines=?
		WHERE analysis_id=? AND ordinal=?`,
		uncompressed, digest, total, accepted, rejected, skipped, s.analysisID, ordinal,
	)
	if err != nil {
		return err
	}
	return requireOneRow(result, "source is not running")
}

func (s *Store) SaveParseError(ctx context.Context, ordinal int, line int64, code string) error {
	_, err := s.database.ExecContext(ctx, `
		INSERT INTO parse_errors (analysis_id, source_ordinal, line_number, code)
		VALUES (?, ?, ?, ?)`, s.analysisID, ordinal, line, code)
	return err
}

func (s *Store) CompleteAnalysis(ctx context.Context, summary aggregate.Summary) error {
	if !conserved(summary.TotalLines, summary.Accepted, summary.Rejected, summary.Skipped) {
		return errors.New("analysis counter conservation failed")
	}
	if (summary.FirstEventUS == nil) != (summary.LastEventUS == nil) ||
		summary.FirstEventUS != nil && *summary.FirstEventUS > *summary.LastEventUS {
		return errors.New("analysis event range is inverted")
	}
	var cellRequests int64
	if err := s.database.QueryRowContext(ctx,
		"SELECT coalesce(sum(requests),0) FROM traffic_cells WHERE analysis_id=?", s.analysisID,
	).Scan(&cellRequests); err != nil {
		return err
	}
	if cellRequests != summary.Accepted {
		return errors.New("traffic cell conservation failed")
	}
	finished := time.Now().UTC().UnixMicro()
	result, err := s.database.ExecContext(ctx, `
		UPDATE analyses SET status='completed', finished_at_us=?, first_event_at_us=?,
			last_event_at_us=?, total_lines=?, accepted_lines=?, rejected_lines=?, skipped_lines=?,
			total_bytes=?, request_duration_us=?, upstream_duration_us=?, rate_model_requests=?,
			route_overflow_requests=?, ua_overflow_requests=?
		WHERE id=? AND status='running'`,
		finished, summary.FirstEventUS, summary.LastEventUS, summary.TotalLines, summary.Accepted,
		summary.Rejected, summary.Skipped, summary.BytesSent, summary.RequestDurationUS,
		summary.UpstreamDurationUS, summary.RateModeled, summary.RouteOverflow, summary.UAOverflow,
		s.analysisID,
	)
	if err != nil {
		return err
	}
	return requireOneRow(result, "analysis is not running")
}

func conserved(total, accepted, rejected, skipped int64) bool {
	if total < 0 || accepted < 0 || rejected < 0 || skipped < 0 ||
		accepted > math.MaxInt64-rejected {
		return false
	}
	sum := accepted + rejected
	return sum <= math.MaxInt64-skipped && sum+skipped == total
}

func requireOneRow(result sql.Result, message string) error {
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return errors.New(message)
	}
	return nil
}

func (s *Store) FailAnalysis(ctx context.Context, code, message, status string) error {
	if status != "failed" && status != "canceled" {
		return errors.New("invalid failure status")
	}
	_, err := s.database.ExecContext(ctx, `
		UPDATE analyses SET status=?, finished_at_us=?, failure_code=?, failure_message=?
		WHERE id=? AND status='running'`,
		status, time.Now().UTC().UnixMicro(), code, message, s.analysisID,
	)
	return err
}

func (s *Store) SaveFindings(ctx context.Context, findings []domain.Finding) error {
	transaction, err := s.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, finding := range findings {
		evidence, err := json.Marshal(finding.Evidence)
		if err != nil {
			_ = transaction.Rollback()
			return err
		}
		var routeID *int64
		if finding.Route != nil {
			var id int64
			err = transaction.QueryRowContext(ctx, `
				SELECT id FROM routes WHERE analysis_id=? AND normalized_path=?
				ORDER BY id LIMIT 1`, s.analysisID, *finding.Route).Scan(&id)
			if err == nil {
				routeID = &id
			} else if !errors.Is(err, sql.ErrNoRows) {
				_ = transaction.Rollback()
				return err
			}
		}
		_, err = transaction.ExecContext(ctx, `
			INSERT INTO findings (
				id, analysis_id, kind, severity, title, summary, route_id, subject_key,
				confidence, recommended_action, evidence_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			finding.ID, s.analysisID, finding.Kind, finding.Severity, finding.Title, finding.Summary,
			routeID, finding.Subject, finding.Confidence, finding.RecommendedAction, string(evidence),
		)
		if err != nil {
			_ = transaction.Rollback()
			return err
		}
	}
	return transaction.Commit()
}

func (s *Store) Optimize(ctx context.Context) error {
	if _, err := s.database.ExecContext(ctx, "ANALYZE"); err != nil {
		return err
	}
	_, err := s.database.ExecContext(ctx, "PRAGMA optimize")
	return err
}

func (s *Store) Checkpoint(ctx context.Context) error {
	var busy, logFrames, checkpointed int
	if err := s.database.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil {
		return err
	}
	if busy != 0 {
		return fmt.Errorf("WAL checkpoint busy")
	}
	return nil
}
