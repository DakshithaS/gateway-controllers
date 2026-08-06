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

package oauth2generator

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// loadCACertPool reads a PEM-encoded CA certificate file and returns a pool
// containing it, for TLS connections that must trust a private/internal CA
// - used by the token endpoint's Transport (oauth2_generator.go's
// buildTokenEndpointTransport).
func loadCACertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no valid PEM certificates found in %q", path)
	}
	return pool, nil
}

// redisConnKey identifies a distinct Redis connection configuration. Two
// policy instances with identical connection settings share one
// *redis.Client (one pool) - mirrors advanced-ratelimit's own redis_clients.go.
//
// NOTE(#3056): duplicates sdk/core/utils/redisclient, which exists to share
// one such registry across every Redis-using policy. Reverted to a local
// copy here because sdk/core has no tagged release containing it yet, and a
// local replace directive would force every other statically-linked policy
// onto that same unreleased checkout. Switch back once a release exists.
type redisConnKey struct {
	addr         string
	username     string
	passwordHash string // sha256 hex; keeps the secret out of the in-process map key
	db           int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	poolSize     int
}

// redisClients is the process-wide registry of shared Redis clients. Without it,
// GetPolicy creates a new *redis.Client (a whole connection pool) per policy instance
// and per config reload, leaking pools and exploding Redis connections at scale.
var redisClients = struct {
	mu sync.Mutex
	m  map[redisConnKey]*redis.Client
}{m: make(map[redisConnKey]*redis.Client)}

// hashSensitiveValue returns a SHA-256 hex digest of a secret value, so it can be
// used as part of a lookup key (here, and oauth2ConfigDiscriminator in
// token_cache.go) without the raw secret appearing in it.
func hashSensitiveValue(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// getOrCreateRedisClient returns the process-wide shared client for these connection
// settings, creating it on first use. Construction always succeeds regardless of
// whether Redis is reachable - go-redis connects lazily on the first command, and any
// error there is handled by the caller per the configured failureMode.
func getOrCreateRedisClient(opts *redis.Options) *redis.Client {
	key := redisConnKey{
		addr:         opts.Addr,
		username:     opts.Username,
		passwordHash: hashSensitiveValue(opts.Password),
		db:           opts.DB,
		dialTimeout:  opts.DialTimeout,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		poolSize:     opts.PoolSize,
	}

	redisClients.mu.Lock()
	defer redisClients.mu.Unlock()

	if c, ok := redisClients.m[key]; ok {
		return c
	}

	c := redis.NewClient(opts)
	redisClients.m[key] = c
	return c
}
