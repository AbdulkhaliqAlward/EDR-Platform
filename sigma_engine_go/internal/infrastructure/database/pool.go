// Package database provides PostgreSQL database connectivity and repositories.
package database

import (
	"context"
	"fmt"
	"github.com/edr-platform/shared/pagination"
	"os"
	"time"

	"github.com/edr-platform/sigma-engine/internal/infrastructure/logger"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Config contains database connection configuration.
type Config struct {
	Host              string        `yaml:"host"`
	Port              int           `yaml:"port"`
	Database          string        `yaml:"database"`
	User              string        `yaml:"user"`
	Password          string        `yaml:"password"`
	SSLMode           string        `yaml:"ssl_mode"`
	MaxConns          int32         `yaml:"max_conns"`
	MinConns          int32         `yaml:"min_conns"`
	MaxConnLifetime   time.Duration `yaml:"max_conn_lifetime"`
	MaxConnIdleTime   time.Duration `yaml:"max_conn_idle_time"`
	HealthCheckPeriod time.Duration `yaml:"health_check_period"`
}

// DefaultConfig returns default database configuration.
func DefaultConfig() Config {
	return Config{
		Host:              "localhost",
		Port:              5432,
		Database:          "edr_platform",
		User:              "postgres",
		Password:          "",
		SSLMode:           "prefer",
		MaxConns:          25,
		MinConns:          5,
		MaxConnLifetime:   30 * time.Minute,
		MaxConnIdleTime:   5 * time.Minute,
		HealthCheckPeriod: 30 * time.Second,
	}
}

// LoadFromEnv loads database configuration from environment variables.
func LoadFromEnv() Config {
	cfg := DefaultConfig()

	if v := os.Getenv("DATABASE_HOST"); v != "" {
		cfg.Host = v
	}
	if v := os.Getenv("DATABASE_PORT"); v != "" {
		var port int
		if _, err := fmt.Sscanf(v, "%d", &port); err == nil {
			cfg.Port = port
		}
	}
	if v := os.Getenv("DATABASE_NAME"); v != "" {
		cfg.Database = v
	}
	if v := os.Getenv("DATABASE_USER"); v != "" {
		cfg.User = v
	}
	if v := os.Getenv("DATABASE_PASSWORD"); v != "" {
		cfg.Password = v
	}
	if v := os.Getenv("DATABASE_SSL_MODE"); v != "" {
		cfg.SSLMode = v
	}
	// Also support connection string
	if v := os.Getenv("DATABASE_URL"); v != "" {
		// Will be parsed directly by pgxpool
	}

	return cfg
}

// ConnectionString builds a PostgreSQL connection string.
func (c Config) ConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.Database, c.SSLMode,
	)
}

// Pool wraps pgxpool.Pool with additional functionality.
type Pool struct {
	pool   *pgxpool.Pool
	config Config
}

// NewPool creates a new database connection pool.
func NewPool(ctx context.Context, cfg Config) (*Pool, error) {
	// Build connection string
	connString := cfg.ConnectionString()

	// Check for DATABASE_URL override
	if url := os.Getenv("DATABASE_URL"); url != "" {
		connString = url
		logger.Infof("Connected to PostgreSQL via DATABASE_URL (pool: %d-%d conns)", cfg.MinConns, cfg.MaxConns)
	} else {
		logger.Infof("Connected to PostgreSQL: %s:%d/%s (pool: %d-%d conns)",
			cfg.Host, cfg.Port, cfg.Database, cfg.MinConns, cfg.MaxConns)
	}

	// Configure pool
	poolConfig, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database config: %w", err)
	}

	pagination.ConfigureKey([]byte(poolConfig.ConnConfig.Password))

	poolConfig.MaxConns = cfg.MaxConns
	poolConfig.MinConns = cfg.MinConns
	poolConfig.MaxConnLifetime = cfg.MaxConnLifetime
	poolConfig.MaxConnIdleTime = cfg.MaxConnIdleTime
	poolConfig.HealthCheckPeriod = cfg.HealthCheckPeriod

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

	return &Pool{
		pool:   pool,
		config: cfg,
	}, nil
}

// Pool returns the underlying pgxpool.Pool.
func (p *Pool) Pool() *pgxpool.Pool {
	return p.pool
}

// Close closes the connection pool.
func (p *Pool) Close() {
	p.pool.Close()
	logger.Info("Database connection pool closed")
}

// Ping checks database connectivity.
func (p *Pool) Ping(ctx context.Context) error {
	return p.pool.Ping(ctx)
}

// Stats returns pool statistics.
func (p *Pool) Stats() *pgxpool.Stat {
	return p.pool.Stat()
}

// HealthCheck performs a health check on the database connection.
func (p *Pool) HealthCheck(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	var result int
	err := p.pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}
