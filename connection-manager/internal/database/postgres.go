// Package database provides PostgreSQL connection management.
package database

import (
	"context"
	"fmt"
	"github.com/edr-platform/shared/pagination"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/sirupsen/logrus"
)

// PostgresConfig holds PostgreSQL connection settings.
type PostgresConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Database        string
	SSLMode         string
	MaxConns        int32
	MinConns        int32
	MaxConnLifetime time.Duration
	MaxConnIdleTime time.Duration
}

// ConnectionString returns the PostgreSQL connection string.
func (c *PostgresConfig) ConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// PostgresPool wraps the pgx connection pool.
type PostgresPool struct {
	pool   *pgxpool.Pool
	logger *logrus.Logger
}

// NewPostgresPool creates a new PostgreSQL connection pool.
func NewPostgresPool(ctx context.Context, cfg *PostgresConfig, logger *logrus.Logger) (*PostgresPool, error) {
	poolConfig, err := pgxpool.ParseConfig(cfg.ConnectionString())
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection string: %w", err)
	}

	pagination.ConfigureKey([]byte(poolConfig.ConnConfig.Password))

	// Set pool configuration
	poolConfig.MaxConns = cfg.MaxConns
	if poolConfig.MaxConns == 0 {
		poolConfig.MaxConns = 25
	}
	poolConfig.MinConns = cfg.MinConns
	if poolConfig.MinConns == 0 {
		poolConfig.MinConns = 5
	}
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	if poolConfig.MaxConnLifetime == 0 {
		poolConfig.MaxConnLifetime = 5 * time.Minute
	}
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	if poolConfig.MaxConnIdleTime == 0 {
		poolConfig.MaxConnIdleTime = 5 * time.Minute
	}

	// Create pool
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"host":      cfg.Host,
		"database":  cfg.Database,
		"max_conns": poolConfig.MaxConns,
	}).Info("Connected to PostgreSQL")

	return &PostgresPool{
		pool:   pool,
		logger: logger,
	}, nil
}

// Pool returns the underlying pgxpool.Pool.
func (p *PostgresPool) Pool() *pgxpool.Pool {
	return p.pool
}

// Close closes the connection pool.
func (p *PostgresPool) Close() {
	p.pool.Close()
	p.logger.Info("PostgreSQL connection pool closed")
}

// Health checks the database health.
func (p *PostgresPool) Health(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// Stats returns pool statistics.
func (p *PostgresPool) Stats() *pgxpool.Stat {
	return p.pool.Stat()
}
