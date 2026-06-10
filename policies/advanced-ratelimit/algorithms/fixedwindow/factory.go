/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package fixedwindow

import (
	"fmt"
	"time"

	"github.com/wso2/gateway-controllers/policies/advanced-ratelimit/limiter"
)

func init() {
	// Register fixed-window algorithm with the factory
	limiter.RegisterAlgorithm("fixed-window", NewLimiter)
}

// NewLimiter creates a fixed window rate limiter based on the provided configuration
func NewLimiter(config limiter.Config) (limiter.Limiter, error) {
	// Convert generic limit configs to fixed-window-specific Policy structs
	policies := convertLimits(config.Limits)

	if len(policies) == 0 {
		return nil, fmt.Errorf("at least one limit must be specified")
	}

	// Create limiter based on backend
	if config.Backend == "redis" {
		if config.RedisClient == nil {
			return nil, fmt.Errorf("redis client is required for redis backend")
		}

		if len(policies) == 1 {
			// Single limiter
			return NewRedisLimiter(config.RedisClient, policies[0], config.KeyPrefix), nil
		}

		// Multi-limiter for Redis
		limiters := make([]limiter.Limiter, len(policies))
		for i, policy := range policies {
			// Use different key prefix for each policy
			policyPrefix := fmt.Sprintf("%sp%d:", config.KeyPrefix, i)
			limiters[i] = NewRedisLimiter(config.RedisClient, policy, policyPrefix)
		}
		return NewMultiLimiter(limiters...), nil
	}

	// Redis-local-async backend: local-first hot path + async Redis reconciliation.
	// Wraps a RedisLimiter (which supplies the key scheme + atomic cost methods).
	if config.Backend == "redis-local-async" {
		if config.RedisClient == nil {
			return nil, fmt.Errorf("redis client is required for redis-local-async backend")
		}

		lac := localAsyncConfig(config.AlgorithmConfig)

		if len(policies) == 1 {
			backing := NewRedisLimiter(config.RedisClient, policies[0], config.KeyPrefix)
			return NewRedisLocalAsyncLimiter(backing, lac), nil
		}

		// Multi-limiter: one async limiter per policy, with a per-policy key prefix.
		limiters := make([]limiter.Limiter, len(policies))
		for i, policy := range policies {
			policyPrefix := fmt.Sprintf("%sp%d:", config.KeyPrefix, i)
			backing := NewRedisLimiter(config.RedisClient, policy, policyPrefix)
			limiters[i] = NewRedisLocalAsyncLimiter(backing, lac)
		}
		return NewMultiLimiter(limiters...), nil
	}

	// Memory backend
	if len(policies) == 1 {
		// Single limiter
		return NewMemoryLimiter(policies[0], config.CleanupInterval), nil
	}

	// Multi-limiter for memory
	limiters := make([]limiter.Limiter, len(policies))
	for i, policy := range policies {
		limiters[i] = NewMemoryLimiter(policy, config.CleanupInterval)
	}
	return NewMultiLimiter(limiters...), nil
}

// localAsyncConfig extracts the redis-local-async tuning from Config.AlgorithmConfig.
// Values are tolerant: syncInterval accepts a time.Duration or a Go-duration string;
// failOpen accepts a bool; the int knobs accept int/int64/float64. Missing/invalid
// values fall back to the defaults (applied in LocalAsyncConfig.withDefaults).
func localAsyncConfig(cfg map[string]interface{}) LocalAsyncConfig {
	out := LocalAsyncConfig{SyncInterval: DefaultSyncInterval, FailOpen: true}
	if cfg == nil {
		return out
	}
	switch d := cfg["syncInterval"].(type) {
	case time.Duration:
		if d > 0 {
			out.SyncInterval = d
		}
	case string:
		if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
			out.SyncInterval = parsed
		}
	}
	if v, ok := cfg["failOpen"].(bool); ok {
		out.FailOpen = v
	}
	out.MaxLocalEntries = intFromAny(cfg["maxLocalEntries"])
	out.FlushWorkers = intFromAny(cfg["flushWorkers"])
	out.MaxPipelineCommands = intFromAny(cfg["maxPipelineCommands"])
	return out
}

// intFromAny coerces an AlgorithmConfig value (int/int64/float64) to int; 0 otherwise.
func intFromAny(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// convertLimits converts generic LimitConfig to fixed-window-specific Policy
func convertLimits(limits []limiter.LimitConfig) []*Policy {
	policies := make([]*Policy, len(limits))
	for i, limit := range limits {
		// For fixed window, burst parameter is not used
		// The limit itself is the maximum per window
		policies[i] = NewPolicy(limit.Limit, limit.Duration)
	}
	return policies
}
