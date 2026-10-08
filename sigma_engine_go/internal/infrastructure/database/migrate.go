// Package database provides auto-migration for PostgreSQL schema.
package database

import (
	"context"
	"embed"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationFS embed.FS

// RunMigrations executes all embedded *.up.sql migration files in lexicographic
// order. Each migration uses IF NOT EXISTS / IF NOT EXISTS guards, making this
// safe to call on every startup (idempotent).
func RunMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("failed to read embedded migrations: %w", err)
	}

	// Collect and sort .up.sql files
	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, e.Name())
		}
	}
	sort.Strings(upFiles)

	if len(upFiles) == 0 {
		logger.Warn("No migration files found")
		return nil
	}

	logger.Infof("Running %d database migrations...", len(upFiles))

	for _, filename := range upFiles {
		sqlBytes, err := migrationFS.ReadFile(path.Join("migrations", filename))
		if err != nil {
			return fmt.Errorf("failed to read migration %s: %w", filename, err)
		}

		sql := string(sqlBytes)
		if strings.TrimSpace(sql) == "" {
			continue
		}

		_, err = pool.Exec(ctx, sql)
		if err != nil {
			return fmt.Errorf("failed to execute migration %s: %w", filename, err)
		}

		logger.Infof("✅ Migration applied: %s", filename)
	}

	logger.Info("All database migrations completed successfully")
	return nil
}
