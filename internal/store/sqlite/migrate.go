package sqlite

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

const CurrentSchemaVersion = 1

func Migrate(ctx context.Context, database *sql.DB) error {
	var version int
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > CurrentSchemaVersion {
		return errors.New("workspace is newer than this binary")
	}
	if version == CurrentSchemaVersion {
		var count int
		if err := database.QueryRowContext(ctx,
			"SELECT count(*) FROM schema_migrations WHERE version = ?", CurrentSchemaVersion,
		).Scan(&count); err != nil || count != 1 {
			return errors.New("schema migration record is missing")
		}
		return quickCheck(ctx, database)
	}
	if version != 0 {
		return errors.New("unsupported schema version")
	}
	script, err := migrationFiles.ReadFile("migrations/001_initial.sql")
	if err != nil {
		return fmt.Errorf("read migration: %w", err)
	}
	transaction, err := database.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, string(script)); err != nil {
		return errors.Join(fmt.Errorf("execute migration: %w", err), transaction.Rollback())
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	if err := database.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil || version != CurrentSchemaVersion {
		return errors.New("migration did not set schema version")
	}
	return quickCheck(ctx, database)
}

func quickCheck(ctx context.Context, database *sql.DB) error {
	var result string
	if err := database.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&result); err != nil {
		return fmt.Errorf("quick check: %w", err)
	}
	if result != "ok" {
		return errors.New("sqlite quick check failed")
	}
	return nil
}
