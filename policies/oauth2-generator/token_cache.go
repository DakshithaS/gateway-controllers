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
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
	xoauth2 "golang.org/x/oauth2"
)

// localTokenCacheKey is the sole key ever used in a redisCachingTokenSource's
// localCache - each instance holds exactly one credential (its own), so
// there's nothing to key on beyond a fixed constant.
var localTokenCacheKey = cache.CacheKey{Key: "token"}

const (
	// FailureModeOpen degrades to fetching directly from the token endpoint
	// when Redis is unavailable, so authentication keeps working through a
	// Redis outage.
	FailureModeOpen = "open"
	// FailureModeClosed treats a Redis error as a token-acquisition failure.
	FailureModeClosed = "closed"

	// CacheStrategyMemory caches tokens in-process only, per gateway-runtime
	// replica - no external dependency. The default, and the only tier used
	// unless CacheStrategyRedis is selected.
	CacheStrategyMemory = "memory"
	// CacheStrategyRedis adds a shared Redis tier in front of the token
	// endpoint - see redisParams. Mirrors Kong's upstream-oauth plugin's
	// cache_strategy setting.
	CacheStrategyRedis = "redis"

	defaultRedisHost              = "localhost"
	defaultRedisPort              = 6379
	defaultRedisKeyPrefix         = "oauth2-generator:token:v1:"
	defaultRedisConnectionTimeout = 5 * time.Second
	defaultRedisReadTimeout       = 3 * time.Second
	defaultRedisWriteTimeout      = 3 * time.Second
)

// redisParams bundles the extracted, validated systemParameters.redis
// values. All fields have sane defaults (see policy-definition.yaml), so
// omitting the whole "redis" block is always valid. Only read/used at all
// when cacheParams.strategy is CacheStrategyRedis - see newRedisCachingTokenSource.
type redisParams struct {
	host              string
	port              int
	username          string
	password          string
	db                int
	keyPrefix         string
	failureMode       string
	connectionTimeout time.Duration
	readTimeout       time.Duration
	writeTimeout      time.Duration
	poolSize          int
}

// cacheParams bundles the extracted, validated params that control caching:
// which tier(s) to use (cacheStrategy, a regular per-config param) and, when
// it's CacheStrategyRedis, the operator-level systemParameters.redis
// connection settings.
type cacheParams struct {
	strategy string
	redis    redisParams
}

// extractCacheParams reads cacheStrategy and systemParameters.redis.* from params,
// falling back to policy-definition.yaml's defaults for anything absent/wrong-typed.
// Nothing here is required - Redis is opt-in via cacheStrategy, not mandatory.
func extractCacheParams(params map[string]interface{}) cacheParams {
	return cacheParams{
		strategy: getNestedStringParam(params, "cacheStrategy", CacheStrategyMemory),
		redis: redisParams{
			host:              getNestedStringParam(params, "redis.host", defaultRedisHost),
			port:              getNestedIntParam(params, "redis.port", defaultRedisPort),
			username:          getNestedStringParam(params, "redis.username", ""),
			password:          getNestedStringParam(params, "redis.password", ""),
			db:                getNestedIntParam(params, "redis.db", 0),
			keyPrefix:         getNestedStringParam(params, "redis.keyPrefix", defaultRedisKeyPrefix),
			failureMode:       getNestedStringParam(params, "redis.failureMode", FailureModeOpen),
			connectionTimeout: getNestedDurationParam(params, "redis.connectionTimeout", defaultRedisConnectionTimeout),
			readTimeout:       getNestedDurationParam(params, "redis.readTimeout", defaultRedisReadTimeout),
			writeTimeout:      getNestedDurationParam(params, "redis.writeTimeout", defaultRedisWriteTimeout),
			poolSize:          getNestedIntParam(params, "redis.poolSize", 0),
		},
	}
}

// getNestedParam resolves a dotted key ("redis.host") against params, tolerating
// either nested maps (params["redis"]["host"]) or a flattened key
// (params["redis.host"]) - systemParameters can arrive either way.
func getNestedParam(params map[string]interface{}, dottedKey string) (interface{}, bool) {
	if v, ok := params[dottedKey]; ok {
		return v, true
	}
	var cur interface{} = params
	for _, part := range strings.Split(dottedKey, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		v, ok := m[part]
		if !ok {
			return nil, false
		}
		cur = v
	}
	return cur, true
}

func getNestedStringParam(params map[string]interface{}, dottedKey, def string) string {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return def
}

func getNestedIntParam(params map[string]interface{}, dottedKey string, def int) int {
	if v, ok := getNestedParam(params, dottedKey); ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		case string:
			if parsed, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
				return parsed
			}
		}
	}
	return def
}

func getNestedDurationParam(params map[string]interface{}, dottedKey string, def time.Duration) time.Duration {
	if v, ok := getNestedParam(params, dottedKey); ok {
		if s, ok := v.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(s)); err == nil {
				return d
			}
		}
	}
	return def
}

// buildRedisKey scopes the cached token to a config discriminator - see
// oauth2ConfigDiscriminator.
func buildRedisKey(prefix, discriminator string) string {
	candidates := []string{strings.TrimSuffix(prefix, ":"), discriminator}
	var parts []string
	for _, s := range candidates {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, ":")
}

// oauth2CacheKeyFields is the subset of oauth2Params that determines what token the
// endpoint would issue and who's entitled to it. Serialized as a struct (fixed
// field order) rather than delimiter-joined, so no field combination can collide.
type oauth2CacheKeyFields struct {
	GrantType        string `json:"grantType"`
	TokenEndpoint    string `json:"tokenEndpoint"`
	ClientID         string `json:"clientId"`
	ClientAuthMethod string `json:"clientAuthMethod"`
	Username         string `json:"username,omitempty"`

	// Params (scope, audience, ...) must be part of the discriminator: a different
	// scope earns a different key. encoding/json sorts map keys alphabetically, so
	// this stays stable regardless of map iteration order.
	Params map[string]string `json:"params,omitempty"`

	// Headers (tokenRequestHeaders), for the same reason as Params: a header some
	// IdPs use to select a sub-tenant/audience changes what token gets minted.
	Headers map[string]string `json:"headers,omitempty"`

	// ClientSecretHash and PasswordHash bind the cache entry to the specific
	// credential presented - see oauth2ConfigDiscriminator.
	ClientSecretHash string `json:"clientSecretHash"`
	PasswordHash     string `json:"passwordHash,omitempty"`
}

// hashSensitiveValue returns a SHA-256 hex digest of a secret value, so it
// can be used as part of oauth2ConfigDiscriminator's cache-key material
// below without the raw secret appearing in it.
func hashSensitiveValue(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// oauth2ConfigDiscriminator derives a stable cache-key component from the oauth2
// config: every field that determines what token the endpoint would issue feeds
// into the hash, so a rotated clientSecret/password lands on a different key while
// byte-identical configs share one, regardless of which API/provider they're on.
//
// clientSecret/password are hashed with SHA-256 rather than stored raw (Redis key
// names appear in MONITOR/slowlog output - see hashSensitiveValue above),
// closing a cross-credential reuse gap: two configs sharing only
// clientId/tokenEndpoint but different credentials now land on different keys.
func oauth2ConfigDiscriminator(p oauth2Params) string {
	fields := oauth2CacheKeyFields{
		GrantType:        p.grantType,
		TokenEndpoint:    p.tokenEndpoint,
		ClientID:         p.clientID,
		ClientAuthMethod: p.clientAuthMethod,
		Username:         p.username,
		Params:           p.tokenRequestParams,
		Headers:          p.tokenRequestHeaders,
		ClientSecretHash: hashSensitiveValue(p.clientSecret),
		PasswordHash:     hashSensitiveValue(p.password),
	}
	// Marshaling a struct of plain strings and a map[string]string cannot
	// fail; the error is only checked to satisfy static analysis.
	data, err := json.Marshal(fields)
	if err != nil {
		data = []byte(fmt.Sprintf("%+v", fields))
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// cachedToken is the JSON shape stored in Redis - just the fields needed to
// reconstruct an xoauth2.Token.
type cachedToken struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry"`
}

// tokenProvider is satisfied by redisCachingTokenSource. Token() mirrors
// xoauth2.TokenSource; Purge clears both cache tiers (see OnResponseHeaders).
type tokenProvider interface {
	Token() (*xoauth2.Token, error)
	Purge()
}

// redisCachingTokenSource wraps a real, IDP-fetching xoauth2.TokenSource with a
// cache of up to two tiers: (1) a per-process in-memory token, always active, and
// (2) a shared Redis entry that lets every replica reuse the same token and
// survives a restart - opt-in via cacheStrategy: redis (redisClient is nil and
// this tier fully skipped under the default cacheStrategy: memory). When active,
// a Redis error either falls back to the token endpoint (failOpen, the default) or
// surfaces as a failure, per redis.failureMode.
type redisCachingTokenSource struct {
	// inner is read/written under mu (mu guards only inner - localCache is its
	// own thread-safe SDK cache) - Purge() replaces it with a freshly-built
	// one. Always a *resilientTokenSource wrapping buildTokenSource's raw output.
	inner xoauth2.TokenSource

	// params is what inner was built from, retained so Purge() can rebuild it.
	params oauth2Params

	redisClient  *redis.Client // nil disables the Redis tier entirely
	failOpen     bool
	readTimeout  time.Duration
	writeTimeout time.Duration

	// defaultTTL is applied to a freshly-fetched token whose Expiry is zero - see
	// its use site in Token().
	defaultTTL time.Duration

	// expiryBuffer is how far ahead of a token's actual expiry both cache
	// tiers stop trusting it - see tokenFreshEnough and oauth2Params.expiryBuffer's
	// field comment for why this must match the threshold buildTokenSource's
	// inner ReuseTokenSourceWithExpiry uses.
	expiryBuffer time.Duration

	mu sync.Mutex

	// localCache holds this instance's single cached token - a size-1
	// SDK cache (see backend-jwt/opaque-token-auth for the same package used
	// for their own, genuinely multi-entry token caches) rather than a
	// hand-rolled field, for consistency across the policy set. Its own TTL
	// support isn't used (ttl=0, never expires per the cache's own check) -
	// tokenFreshEnough applies the dynamic, per-token expiryBuffer margin on
	// every read instead, which a single fixed cache-wide TTL can't express.
	localCache *cache.InMemoryCache[xoauth2.Token]

	// redisKey is fixed at construction from oauth2ConfigDiscriminator - it
	// depends only on the config, never anything request-time.
	redisKey string
}

// newRedisCachingTokenSource builds the cache wrapper around inner (built from the
// same p), deriving the Redis key and TTL fallback and retaining p so Purge() can
// rebuild inner later. The Redis client is only constructed when cp.strategy is
// CacheStrategyRedis - under the default memory strategy, every Redis-tier path is
// skipped.
func newRedisCachingTokenSource(inner xoauth2.TokenSource, cp cacheParams, p oauth2Params) tokenProvider {
	var client *redis.Client
	if cp.strategy == CacheStrategyRedis {
		// created/pingErr deliberately ignored: this policy's own failOpen/
		// failClosed handling already covers a down Redis at the point of
		// first real use (getFromRedis/saveToRedis) - adopting
		// getOrCreateRedisClient's create-time ping-and-fail-fast behavior
		// too would change *when* a failClosed+Redis-down error surfaces
		// (at policy-chain-build time instead of first request), a real
		// behavior change this call site isn't opting into.
		client, _, _ = getOrCreateRedisClient(&redis.Options{
			Addr:         fmt.Sprintf("%s:%d", cp.redis.host, cp.redis.port),
			Username:     cp.redis.username,
			Password:     cp.redis.password,
			DB:           cp.redis.db,
			DialTimeout:  cp.redis.connectionTimeout,
			ReadTimeout:  cp.redis.readTimeout,
			WriteTimeout: cp.redis.writeTimeout,
			PoolSize:     cp.redis.poolSize,
		}, cp.redis.connectionTimeout)
	}

	return &redisCachingTokenSource{
		inner:        newResilientInner(inner, p),
		params:       p,
		redisClient:  client,
		redisKey:     buildRedisKey(cp.redis.keyPrefix, oauth2ConfigDiscriminator(p)),
		failOpen:     cp.redis.failureMode != FailureModeClosed,
		readTimeout:  cp.redis.readTimeout,
		writeTimeout: cp.redis.writeTimeout,
		defaultTTL:   p.tokenTTLFallback,
		expiryBuffer: p.expiryBuffer,
		localCache:   cache.NewInMemoryCache[xoauth2.Token]("oauth2-generator-local-token", 1, 0, cache.LRUEvictionPolicy, slog.Default()),
	}
}

// tokenFreshEnough reports whether tok is both present and far enough from
// its own expiry to still be trusted - the buffer-aware counterpart to
// xoauth2.Token.Valid(), which only ever applies the library's own
// hardcoded, non-configurable 10s margin. A zero Expiry mirrors Valid()'s
// own convention (never expires) - by the time a token reaches either cache
// tier it has already been normalized away from zero (see Token()'s
// defaultTTL fallback), so this only matters for a token handed in directly
// by a test or future caller.
func tokenFreshEnough(tok *xoauth2.Token, buffer time.Duration) bool {
	if tok == nil || tok.AccessToken == "" {
		return false
	}
	if tok.Expiry.IsZero() {
		return true
	}
	return tok.Expiry.Add(-buffer).After(time.Now())
}

// newResilientInner wraps a raw buildTokenSource output with retry (see
// resilientTokenSource) - a small helper so both newRedisCachingTokenSource and
// Purge() build it identically.
func newResilientInner(raw xoauth2.TokenSource, p oauth2Params) xoauth2.TokenSource {
	return &resilientTokenSource{inner: raw, maxRetries: p.tokenRequestMaxRetries}
}

func (s *redisCachingTokenSource) Token() (*xoauth2.Token, error) {
	if tok := s.localToken(); tok != nil {
		return tok, nil
	}

	if s.redisClient != nil {
		tok, err := s.getFromRedis()
		switch {
		case err != nil && !s.failOpen:
			return nil, fmt.Errorf("redis token cache unavailable: %w", err)
		case err != nil:
			slog.Warn("OAuth2Generator: redis token cache unavailable, fetching directly from token endpoint", "error", err)
		case tok != nil:
			s.setLocal(tok)
			return tok, nil
		}
	}

	tok, err := s.getInner().Token()
	if err != nil {
		return nil, err
	}
	if tok.Expiry.IsZero() {
		// Some IdPs omit expires_in, leaving Expiry zero; Token.Valid() treats that
		// as already-expired, so this fallback is what makes it cacheable at all.
		// Mutate a copy - tok may be handed to a concurrent caller by ReuseTokenSource
		// with no lock held over it.
		fixed := *tok
		fixed.Expiry = time.Now().Add(s.defaultTTL)
		tok = &fixed
	}
	s.setLocal(tok)

	if s.redisClient != nil {
		if err := s.saveToRedis(tok); err != nil {
			// Failing to populate the shared cache doesn't invalidate the
			// token we just successfully obtained - log and continue. This
			// replica just won't share it with others until a future write
			// succeeds.
			slog.Warn("OAuth2Generator: failed to write token to redis cache", "error", err)
		}
	}
	return tok, nil
}

func (s *redisCachingTokenSource) localToken() *xoauth2.Token {
	tok, ok := s.localCache.Get(context.Background(), localTokenCacheKey)
	if !ok || !tokenFreshEnough(&tok, s.expiryBuffer) {
		return nil
	}
	return &tok
}

func (s *redisCachingTokenSource) setLocal(tok *xoauth2.Token) {
	_ = s.localCache.Set(context.Background(), localTokenCacheKey, *tok) // never errors - see InMemoryCache.Set
}

func (s *redisCachingTokenSource) getInner() xoauth2.TokenSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner
}

// Purge clears both cache tiers so the next Token() call fetches fresh - used when
// the upstream rejects the token this policy just injected (see OnResponseHeaders).
// Clearing local/Redis alone isn't enough: inner is typically an
// xoauth2.ReuseTokenSource that keeps reusing its own cached token regardless, until
// its own Expiry - only replacing inner with a freshly-built one actually forces a
// real fetch. Rebuilding via buildTokenSource(s.params) can only fail on an
// unsupported grantType, already rejected at construction - if it fails here
// anyway, keep the existing inner rather than leave it nil.
func (s *redisCachingTokenSource) Purge() {
	_ = s.localCache.Delete(context.Background(), localTokenCacheKey)

	s.mu.Lock()
	if fresh, err := buildTokenSource(s.params); err == nil {
		s.inner = newResilientInner(fresh, s.params)
	} else {
		slog.Error("OAuth2Generator: failed to rebuild token source while purging, keeping the existing one", "error", err)
	}
	s.mu.Unlock()

	if s.redisClient == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	if err := s.redisClient.Del(ctx, s.redisKey).Err(); err != nil {
		slog.Warn("OAuth2Generator: failed to purge redis token cache entry", "error", err)
	}
}

func (s *redisCachingTokenSource) getFromRedis() (*xoauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
	defer cancel()

	val, err := s.redisClient.Get(ctx, s.redisKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var ct cachedToken
	if err := json.Unmarshal([]byte(val), &ct); err != nil {
		return nil, fmt.Errorf("failed to decode cached token: %w", err)
	}

	tok := &xoauth2.Token{
		AccessToken:  ct.AccessToken,
		TokenType:    ct.TokenType,
		RefreshToken: ct.RefreshToken,
		Expiry:       ct.Expiry,
	}
	if !tokenFreshEnough(tok, s.expiryBuffer) {
		// Not just defensive: unlike Valid()'s hardcoded 10s, expiryBuffer
		// can be large enough that a replica reads this entry, per its own
		// freshness threshold, well before the Redis TTL naturally expires
		// it - falling through here (rather than trusting Redis's mere
		// presence) is what makes that replica refetch instead of serving a
		// token the caller configured it not to trust anymore.
		return nil, nil
	}
	return tok, nil
}

func (s *redisCachingTokenSource) saveToRedis(tok *xoauth2.Token) error {
	ttl := time.Until(tok.Expiry)
	if ttl <= 0 {
		// No usable expiry to derive a TTL from - nothing safe to cache.
		return nil
	}

	data, err := json.Marshal(cachedToken{
		AccessToken:  tok.AccessToken,
		TokenType:    tok.TokenType,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
	})
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.writeTimeout)
	defer cancel()
	return s.redisClient.Set(ctx, s.redisKey, data, ttl).Err()
}
