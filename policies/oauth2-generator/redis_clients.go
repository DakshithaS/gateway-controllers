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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// keyedSingleton is a process-wide registry of shared values, built once per
// distinct key and kept for the life of the process - the pattern both
// redisClients below and the token-endpoint transport registry
// (oauth2_generator.go) need, previously hand-rolled independently by each
// (and already drifted: one released its lock before slow work, the other
// didn't).
//
// build is always called OUTSIDE the lock, so a slow or blocking build (a
// disk read, a network dial/ping) for one key can never stall get-or-create
// calls for a different key, or even a concurrent call for the SAME key that
// only needs to read the map. A benign race where two callers build
// concurrently for the same not-yet-cached key is resolved by discarding the
// loser's build in favor of whichever finished first - never by serializing
// builds behind the lock.
type keyedSingleton[K comparable, V any] struct {
	mu sync.Mutex
	m  map[K]V
}

func newKeyedSingleton[K comparable, V any]() *keyedSingleton[K, V] {
	return &keyedSingleton[K, V]{m: make(map[K]V)}
}

// getOrCreate returns the cached value for key, or the result of calling
// build (outside the lock) on a miss. created reports whether THIS call's
// build won the race and became the shared value - false both on a
// pre-existing hit and when a concurrent builder for the same key won
// instead, in which case that concurrent builder's value is returned. A
// failed build is never cached; the next caller for the same key retries it.
func (r *keyedSingleton[K, V]) getOrCreate(key K, build func() (V, error)) (value V, created bool, err error) {
	r.mu.Lock()
	if v, ok := r.m[key]; ok {
		r.mu.Unlock()
		return v, false, nil
	}
	r.mu.Unlock()

	v, err := build()
	if err != nil {
		var zero V
		return zero, false, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.m[key]; ok {
		return existing, false, nil
	}
	r.m[key] = v
	return v, true, nil
}

// redisConnKey identifies a distinct Redis connection configuration. Two policy
// instances with identical connection settings share one *redis.Client (one pool).
//
// Excludes TLSConfig and any credentials-provider option - see
// getOrCreateRedisClient's bypass for those.
type redisConnKey struct {
	addr         string
	username     string
	passwordHash string // sha256 hex; keeps the secret out of the in-process map key
	db           int
	protocol     int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	poolSize     int
}

// redisClients is the process-wide registry of shared Redis clients. Without it,
// GetPolicy creates a new *redis.Client (a whole connection pool) per policy instance
// and per config reload, leaking pools and exploding Redis connections at scale. See
// keyedSingleton above for the shared get-or-create pattern - also used by
// oauth2_generator.go's token-endpoint transport registry.
var redisClients = newKeyedSingleton[redisConnKey, *redis.Client]()

func hashRedisPassword(p string) string {
	if p == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(p))
	return hex.EncodeToString(sum[:])
}

// getOrCreateRedisClient returns the process-wide shared client for these connection
// settings, creating (and pinging once) it on first use. created reports whether this
// call created the client; pingErr is non-nil only when created and the initial ping
// failed. The client is registered and returned even on ping failure (go-redis
// reconnects lazily). Clients are never closed — they live for the process lifetime.
func getOrCreateRedisClient(opts *redis.Options, pingTimeout time.Duration) (client *redis.Client, created bool, pingErr error) {
	// TLSConfig and credentials-provider hooks can't be fingerprinted
	// safely: a *tls.Config's pointer says nothing about its content, and
	// Go func values aren't comparable at all. Bypass the registry rather
	// than risk silently reusing a client built for a different config.
	if opts.TLSConfig != nil || opts.CredentialsProvider != nil || opts.CredentialsProviderContext != nil || opts.StreamingCredentialsProvider != nil {
		c := redis.NewClient(opts)
		ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
		defer cancel()
		pingErr = c.Ping(ctx).Err()
		return c, true, pingErr
	}

	key := redisConnKey{
		addr:         opts.Addr,
		username:     opts.Username,
		passwordHash: hashRedisPassword(opts.Password),
		db:           opts.DB,
		protocol:     opts.Protocol,
		dialTimeout:  opts.DialTimeout,
		readTimeout:  opts.ReadTimeout,
		writeTimeout: opts.WriteTimeout,
		poolSize:     opts.PoolSize,
	}

	// getOrCreate's build (redis.NewClient) never blocks - go-redis dials
	// lazily - so the client is registered well before the ping below runs.
	// A concurrent caller for the same key may see the just-inserted client
	// before this ping finishes - fine, since a reused client is already
	// "assumed healthy" regardless of timing, never gated on this call's
	// pingErr. Only the call that actually inserted it (created) pings.
	client, created, _ = redisClients.getOrCreate(key, func() (*redis.Client, error) {
		return redis.NewClient(opts), nil
	})
	if created {
		ctx, cancel := context.WithTimeout(context.Background(), pingTimeout)
		defer cancel()
		pingErr = client.Ping(ctx).Err()
	}
	return client, created, pingErr
}
