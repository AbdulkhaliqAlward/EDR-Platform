// Package cache provides Redis client wrapper for caching and rate limiting.
package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

// RedisClient wraps the Redis client with EDR-specific operations.
type RedisClient struct {
	client *redis.Client
	logger *logrus.Logger
}

// RedisConfig holds Redis connection configuration.
type RedisConfig struct {
	Addr         string
	Password     string
	DB           int
	PoolSize     int
	PoolTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// NewRedisClient creates a new Redis client.
func NewRedisClient(cfg *RedisConfig, logger *logrus.Logger) (*RedisClient, error) {
	return newRedisClient(context.Background(), cfg, logger)
}

func newRedisClient(parent context.Context, cfg *RedisConfig, logger *logrus.Logger) (*RedisClient, error) {
	client := redis.NewClient(&redis.Options{
		Addr:                  cfg.Addr,
		Password:              cfg.Password,
		DB:                    cfg.DB,
		PoolSize:              cfg.PoolSize,
		PoolTimeout:           cfg.PoolTimeout,
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		ContextTimeoutEnabled: true,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	logger.WithField("addr", cfg.Addr).Info("Connected to Redis")

	return &RedisClient{
		client: client,
		logger: logger,
	}, nil
}

// WaitForRedis retries startup while Redis loads its persisted dataset. No
// request handlers may start with a permanently nil security dependency.
func WaitForRedis(ctx context.Context, cfg *RedisConfig, logger *logrus.Logger) (*RedisClient, error) {
	var lastErr error
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("Redis startup deadline: %w (last error: %v)", err, lastErr)
		}
		client, err := newRedisClient(ctx, cfg, logger)
		if err == nil {
			return client, nil
		}
		lastErr = err
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("Redis startup deadline: %w (last error: %v)", ctx.Err(), lastErr)
		case <-timer.C:
		}
	}
}

// Close closes the Redis connection.
func (r *RedisClient) Close() error {
	return r.client.Close()
}

// Client returns the underlying Redis client.
func (r *RedisClient) Client() *redis.Client {
	return r.client
}

// ============================================================================
// AGENT STATUS OPERATIONS
// ============================================================================

// AgentStatusKey returns the Redis key for agent status.
func AgentStatusKey(agentID string) string {
	return fmt.Sprintf("agent:status:%s", agentID)
}

// SetAgentStatus sets the agent's online status.
func (r *RedisClient) SetAgentStatus(ctx context.Context, agentID, status string, ttl time.Duration) error {
	key := AgentStatusKey(agentID)
	data := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().Unix(),
	}

	if err := r.client.HSet(ctx, key, data).Err(); err != nil {
		return fmt.Errorf("failed to set agent status: %w", err)
	}

	if err := r.client.Expire(ctx, key, ttl).Err(); err != nil {
		r.logger.Warnf("Failed to set TTL for agent status: %v", err)
	}

	return nil
}

// GetAgentStatus gets the agent's status from cache.
func (r *RedisClient) GetAgentStatus(ctx context.Context, agentID string) (string, error) {
	key := AgentStatusKey(agentID)
	status, err := r.client.HGet(ctx, key, "status").Result()
	if err == redis.Nil {
		return "offline", nil // Default to offline if not in cache
	}
	if err != nil {
		return "", fmt.Errorf("failed to get agent status: %w", err)
	}
	return status, nil
}

// ============================================================================
// BATCH DEDUPLICATION
// ============================================================================

// BatchKey returns the Redis key for batch deduplication.
func BatchKey(batchID string) string {
	return fmt.Sprintf("batch:%s", batchID)
}

// SetBatchProcessed marks a batch as processed for deduplication.
func (r *RedisClient) SetBatchProcessed(ctx context.Context, batchID string, ttl time.Duration) error {
	key := BatchKey(batchID)
	return r.client.SetEx(ctx, key, "1", ttl).Err()
}

// IsBatchProcessed checks if a batch has already been processed.
func (r *RedisClient) IsBatchProcessed(ctx context.Context, batchID string) (bool, error) {
	key := BatchKey(batchID)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check batch: %w", err)
	}
	return exists > 0, nil
}

// ============================================================================
// TOKEN BLACKLIST
// ============================================================================

// TokenBlacklistKey returns the Redis key for token blacklist.
func TokenBlacklistKey(jti string) string {
	return fmt.Sprintf("token:revoked:%s", jti)
}

// AddToBlacklist adds a token to the blacklist.
func (r *RedisClient) AddToBlacklist(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	key := TokenBlacklistKey(jti)
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // Token already expired
	}

	data := map[string]interface{}{
		"revoked_at": time.Now().Unix(),
		"reason":     reason,
	}

	if err := r.client.HSet(ctx, key, data).Err(); err != nil {
		return fmt.Errorf("failed to add to blacklist: %w", err)
	}

	return r.client.Expire(ctx, key, ttl).Err()
}

// IsBlacklisted checks if a token is in the blacklist.
func (r *RedisClient) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := TokenBlacklistKey(jti)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check blacklist: %w", err)
	}
	return exists > 0, nil
}

// IsTokenBlacklisted is an alias for IsBlacklisted.
func (r *RedisClient) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	return r.IsBlacklisted(ctx, jti)
}

// BlacklistToken is an alias for AddToBlacklist.
func (r *RedisClient) BlacklistToken(ctx context.Context, jti string, expiresAt time.Time, reason string) error {
	return r.AddToBlacklist(ctx, jti, expiresAt, reason)
}

// ============================================================================
// RATE LIMITING
// ============================================================================

// RateLimitKey returns the Redis key for rate limiting.
func RateLimitKey(agentID string, second int64) string {
	return fmt.Sprintf("ratelimit:agent:%s:%d", agentID, second)
}

// RateLimiter provides token bucket rate limiting.
type RateLimiter struct {
	redis           *RedisClient
	eventsPerSecond int
	burstMultiplier float64
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(redis *RedisClient, eventsPerSecond int, burstMultiplier float64) *RateLimiter {
	return &RateLimiter{
		redis:           redis,
		eventsPerSecond: eventsPerSecond,
		burstMultiplier: burstMultiplier,
	}
}

// Allow checks if the request should be allowed based on rate limiting.
// Returns (allowed, current count, error).
// When Redis is unavailable (rl.redis == nil), allows all requests (fail-open).
func (rl *RateLimiter) Allow(ctx context.Context, agentID string, eventCount int) (bool, int64, error) {
	if rl.redis == nil {
		return true, 0, nil
	}
	now := time.Now().Unix()
	key := RateLimitKey(agentID, now)

	// Increment counter
	count, err := rl.redis.client.IncrBy(ctx, key, int64(eventCount)).Result()
	if err != nil {
		return false, 0, fmt.Errorf("failed to increment rate limit counter: %w", err)
	}

	// Set TTL on first access
	if count == int64(eventCount) {
		rl.redis.client.Expire(ctx, key, 61*time.Second)
	}

	// Calculate limit with burst
	limit := int64(float64(rl.eventsPerSecond) * rl.burstMultiplier)

	return count <= limit, count, nil
}

// GetCurrentCount returns the current event count for an agent in the current second.
// When Redis is unavailable (rl.redis == nil), returns 0, nil.
func (rl *RateLimiter) GetCurrentCount(ctx context.Context, agentID string) (int64, error) {
	if rl.redis == nil {
		return 0, nil
	}
	now := time.Now().Unix()
	key := RateLimitKey(agentID, now)

	count, err := rl.redis.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// ============================================================================
// CERTIFICATE REVOCATION
// ============================================================================

// CertRevokedKey returns the Redis key for certificate revocation.
func CertRevokedKey(fingerprint string) string {
	return fmt.Sprintf("cert:revoked:%s", fingerprint)
}

// AddCertToRevocationList adds a certificate fingerprint to the revocation list.
func (r *RedisClient) AddCertToRevocationList(ctx context.Context, fingerprint string, expiresAt time.Time) error {
	key := CertRevokedKey(fingerprint)
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		ttl = 24 * time.Hour // Default to 24h if cert already expired
	}

	return r.client.SetEx(ctx, key, "1", ttl).Err()
}

// IsCertRevoked checks if a certificate is in the revocation list.
func (r *RedisClient) IsCertRevoked(ctx context.Context, fingerprint string) (bool, error) {
	key := CertRevokedKey(fingerprint)
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check cert revocation: %w", err)
	}
	return exists > 0, nil
}

// ============================================================================
// PUB/SUB FOR DASHBOARD NOTIFICATIONS
// ============================================================================

// Publish publishes a message to a channel.
func (r *RedisClient) Publish(ctx context.Context, channel, message string) error {
	return r.client.Publish(ctx, channel, message).Err()
}

// Subscribe subscribes to a channel and returns messages.
func (r *RedisClient) Subscribe(ctx context.Context, channels ...string) *redis.PubSub {
	return r.client.Subscribe(ctx, channels...)
}
