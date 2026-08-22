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
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// ─── test helpers ────────────────────────────────────────────────────────────

// stubTokenSource is a fake "real" token source (standing in for
// buildTokenSource's client_credentials/password fetch) that counts calls so
// tests can assert the Redis/local cache actually prevented a fetch, rather
// than just happening to return the right value.
type stubTokenSource struct {
	calls int
	token *Token
	err   error
}

func (s *stubTokenSource) Token(context.Context) (*Token, error) {
	s.calls++
	if s.err != nil {
		return nil, s.err
	}
	return s.token, nil
}

// mustNewRedisCachingTokenSource wraps newRedisCachingTokenSource for tests.
func mustNewRedisCachingTokenSource(t *testing.T, inner TokenSource, cp cacheParams, p oauth2Params) tokenProvider {
	t.Helper()
	return newRedisCachingTokenSource(inner, cp, p)
}

// testRedisTarget is a real Redis connection for tests that specifically
// exercise the Redis tier - see newTestRedisTarget. client is for direct
// seeding/inspection (the same operations miniredis's own methods used to
// provide); prefix is unique per test so many tests sharing one long-lived
// Redis instance can never collide or leak state into each other.
type testRedisTarget struct {
	host   string
	port   int
	prefix string
	client *redis.Client
}

// newTestRedisTarget connects to a real Redis instance - REDIS_TEST_ADDR if
// set, else localhost:6379 (matches docker-compose.yaml's "redis" service).
// Skips the calling test if nothing is reachable there, so `go test ./...`
// still passes on a machine with no Redis running; CI provides one via a
// services: block (see .github/workflows/release-policy.yml).
func newTestRedisTarget(t *testing.T) *testRedisTarget {
	t.Helper()

	addr := os.Getenv("REDIS_TEST_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("invalid REDIS_TEST_ADDR %q: %v", addr, err)
	}

	// MaxRetries: -1 and a short DialTimeout keep an unreachable-Redis skip
	// fast and quiet - the default retry/backoff behavior is for production
	// resilience, not for a one-shot reachability probe.
	client := redis.NewClient(&redis.Options{Addr: addr, DialTimeout: 300 * time.Millisecond, MaxRetries: -1})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		t.Skipf("no real redis reachable at %s for this test (set REDIS_TEST_ADDR, or start one - see docker-compose.yaml's redis service): %v", addr, err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// Unique per test (name + a fresh nanosecond timestamp, since a test
	// helper can be called more than once per test) so cleanup below can
	// never touch another test's keys even if they ran concurrently.
	prefix := fmt.Sprintf("oauth2-generator-test:%s:%d:", t.Name(), time.Now().UnixNano())
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		iter := client.Scan(cleanupCtx, 0, prefix+"*", 0).Iterator()
		for iter.Next(cleanupCtx) {
			client.Del(cleanupCtx, iter.Val())
		}
	})

	return &testRedisTarget{host: host, port: mustAtoi(portStr), prefix: prefix, client: client}
}

// testRedisParams returns a cacheParams fixture with strategy: redis pointed
// at rt - for tests that specifically exercise the Redis tier. Tests that
// only care about the in-process tier (the default) use testParams() alone
// and never call this.
func testRedisParams(rt *testRedisTarget, failureMode string) cacheParams {
	return cacheParams{
		strategy: CacheStrategyRedis,
		redis: redisParams{
			host:              rt.host,
			port:              rt.port,
			keyPrefix:         rt.prefix,
			failureMode:       failureMode,
			connectionTimeout: time.Second,
			readTimeout:       time.Second,
			writeTimeout:      time.Second,
		},
	}
}

// unreachableRedisParams returns a cacheParams fixture pointed at a host
// that can never answer - for tests simulating Redis being down, which
// don't need (and shouldn't require) a real Redis instance at all.
func unreachableRedisParams(failureMode string) cacheParams {
	return cacheParams{
		strategy: CacheStrategyRedis,
		redis: redisParams{
			host:              "unreachable.invalid",
			port:              1,
			keyPrefix:         "oauth2-generator-test:down:",
			failureMode:       failureMode,
			connectionTimeout: 50 * time.Millisecond,
			readTimeout:       50 * time.Millisecond,
			writeTimeout:      50 * time.Millisecond,
		},
	}
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

// testParams returns a baseline, valid oauth2Params fixture for tests that
// only care about the cache-key/caching behavior, not param validation.
// Pass mutate funcs to override individual fields for a specific case.
func testParams(mutate ...func(*oauth2Params)) oauth2Params {
	p := oauth2Params{
		grantType:        GrantTypeClientCredentials,
		tokenEndpoint:    "https://idp.example.com/token",
		clientID:         "client-a",
		clientSecret:     "s3cr3t",
		clientAuthMethod: ClientAuthMethodBasic,
		defaultTokenTTL:  defaultTokenTTLFallback,
	}
	for _, m := range mutate {
		m(&p)
	}
	return p
}

// ─── oauth2ConfigDiscriminator ──────────────────────────────────────────────

func TestOauth2ConfigDiscriminator_IdenticalConfig_ProducesSameKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams())
	b := oauth2ConfigDiscriminator(testParams())
	if a != b {
		t.Errorf("expected identical oauth2 config to produce the same discriminator, got %q vs %q", a, b)
	}
}

func TestOauth2ConfigDiscriminator_DifferentClientID_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams())
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientID = "client-b" }))
	if a == b {
		t.Error("expected a different clientId to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_DifferentTokenEndpoint_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams())
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenEndpoint = "https://idp-b.example.com/token" }))
	if a == b {
		t.Error("expected a different tokenEndpoint to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_DifferentGrantType_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.grantType = GrantTypeClientCredentials }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.grantType = GrantTypePassword
		p.username = "bob"
	}))
	if a == b {
		t.Error("expected a different grantType to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_DifferentUsername_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.username = "alice" }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.username = "bob" }))
	if a == b {
		t.Error("expected a different username (password grant) to produce a different discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentClientAuthMethod_ProducesDifferentKey
// locks in that clientAuthMethod (client_secret_basic vs client_secret_post)
// is part of the discriminator: it's plausible for two configs to share
// every other field yet differ only in how credentials are presented to the
// token endpoint (e.g. one IdP integration migrating from Basic auth to
// POST body auth) - those requests aren't necessarily equivalent from the
// IdP's perspective, so treating them as separate cache entries is the safe
// default.
func TestOauth2ConfigDiscriminator_DifferentClientAuthMethod_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientAuthMethod = ClientAuthMethodBasic }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientAuthMethod = ClientAuthMethodPost }))
	if a == b {
		t.Error("expected a different clientAuthMethod to produce a different discriminator")
	}
}

// TestOauth2ConfigDiscriminator_NilVsEmptyCustomParams_ProducesSameKey locks
// in that a config with no "tokenRequestParams" set at all (customParams ==
// nil, the client_credentials/no-scope common case) and one with an
// explicitly empty "tokenRequestParams": {} are indistinguishable - both
// mean "no extra token-request fields" and must land on the same cache
// entry, not two different ones for what is operationally the same
// configuration.
func TestOauth2ConfigDiscriminator_NilVsEmptyCustomParams_ProducesSameKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = nil }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = map[string]string{} }))
	if a != b {
		t.Error("expected nil and empty customParams to produce the same discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentScope_ProducesDifferentKey locks in
// the exact bug this discriminator fixes: a proxy's primary provider and an
// additionalProviders entry can share clientId/tokenEndpoint but request
// different scopes (or point at genuinely different providers) - those must
// never share a cached token.
func TestOauth2ConfigDiscriminator_DifferentScope_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = map[string]string{"scope": "read"} }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.tokenRequestParams = map[string]string{"scope": "write"} }))
	if a == b {
		t.Error("expected different scope (via customParams) to produce a different discriminator")
	}
}

func TestOauth2ConfigDiscriminator_ParamsKeyOrder_ProducesSameKey(t *testing.T) {
	// encoding/json sorts map keys when marshaling - locks in that the
	// discriminator doesn't depend on incidental map iteration order.
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.tokenRequestParams = map[string]string{"scope": "read", "audience": "api-a"}
	}))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) {
		p.tokenRequestParams = map[string]string{"audience": "api-a", "scope": "read"}
	}))
	if a != b {
		t.Error("expected customParams map iteration order not to affect the discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentClientSecret_ProducesDifferentKey is
// the regression test for a real bug found via a live end-to-end run: a
// second LlmProvider registered with the same clientId/tokenEndpoint as an
// existing one but a deliberately wrong clientSecret (to test that bad
// credentials are rejected) was instead served the OTHER provider's
// legitimately-cached token from Redis and spuriously succeeded - because an
// earlier version of oauth2ConfigDiscriminator deliberately left clientSecret
// out of the key. clientId and tokenEndpoint alone do not prove two configs
// are the same authorized caller.
func TestOauth2ConfigDiscriminator_DifferentClientSecret_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientSecret = "secret-1" }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.clientSecret = "secret-2" }))
	if a == b {
		t.Error("expected a different clientSecret to produce a different discriminator")
	}
}

// TestOauth2ConfigDiscriminator_DifferentPassword_ProducesDifferentKey is the
// password-grant equivalent of the clientSecret regression above: a wrong
// resource-owner password must not be able to borrow a cached token obtained
// with the correct one.
func TestOauth2ConfigDiscriminator_DifferentPassword_ProducesDifferentKey(t *testing.T) {
	a := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.password = "hunter2" }))
	b := oauth2ConfigDiscriminator(testParams(func(p *oauth2Params) { p.password = "wrong-password" }))
	if a == b {
		t.Error("expected a different password to produce a different discriminator")
	}
}

// ─── buildRedisKey ───────────────────────────────────────────────────────────

func TestBuildRedisKey(t *testing.T) {
	key := buildRedisKey("oauth2-generator:token:v1:", "abc123")
	want := "oauth2-generator:token:v1:abc123"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

func TestBuildRedisKey_OmitsEmptyDiscriminator(t *testing.T) {
	key := buildRedisKey("oauth2-generator:token:v1:", "")
	want := "oauth2-generator:token:v1"
	if key != want {
		t.Errorf("got %q, want %q", key, want)
	}
}

// ─── redisCachingTokenSource ─────────────────────────────────────────────────

func TestRedisCachingTokenSource_CacheMiss_FetchesFromInnerAndStores(t *testing.T) {
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{token: &Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), testParams())

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "fresh-token" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch on cache miss, got %d", inner.calls)
	}

	key := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(testParams()))
	if rt.client.Exists(context.Background(), key).Val() == 0 {
		t.Errorf("expected token to be written to redis under key %q", key)
	}
}

// TestRedisCachingTokenSource_Purge_ClearsLocalAndRedis locks in that Purge
// clears both cache tiers AND rebuilds inner via buildTokenSource, not just
// local/Redis: inner is typically a reuseTokenSource that keeps
// reusing its own cached token until that token's own Expiry regardless of
// local/Redis, so a stub inner (which has no such internal cache) would
// pass even if Purge() only cleared local/Redis and left the real
// buildTokenSource-shaped bug in place - this uses a real httptest server
// through the real buildTokenSource path specifically to catch that.
func TestRedisCachingTokenSource_Purge_ClearsLocalAndRedis(t *testing.T) {
	rt := newTestRedisTarget(t)

	var idpCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpCalls++
		accessToken := "token-1"
		if idpCalls > 1 {
			accessToken = "token-2"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   300,
		})
	}))
	defer server.Close()

	params := testParams(func(p *oauth2Params) { p.tokenEndpoint = server.URL })
	inner, err := buildTokenSource(params)
	if err != nil {
		t.Fatalf("unexpected error building token source: %v", err)
	}
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), params)

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error priming the cache: %v", err)
	}
	if tok.AccessToken != "token-1" {
		t.Fatalf("unexpected primed access token: %q", tok.AccessToken)
	}
	if idpCalls != 1 {
		t.Fatalf("expected exactly 1 token-endpoint call to prime the cache, got %d", idpCalls)
	}
	key := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(params))
	if rt.client.Exists(context.Background(), key).Val() == 0 {
		t.Fatal("expected the primed token to be present in redis")
	}

	src.Purge()

	if rt.client.Exists(context.Background(), key).Val() != 0 {
		t.Error("expected Purge to delete the redis cache entry")
	}

	tok, err = src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "token-2" {
		t.Errorf("expected Purge to force a fresh token-endpoint call, got access token %q", tok.AccessToken)
	}
	if idpCalls != 2 {
		t.Errorf("expected exactly 2 token-endpoint calls total (primed + post-purge), got %d", idpCalls)
	}
}

// TestRedisCachingTokenSource_MissingExpiry_AppliesDefaultTTLFallback locks
// in the fallback for IdPs that omit expires_in entirely: a token response
// with no expires_in leaves Token.Expiry as the zero value, which without
// this fallback would mean caching silently never engages (see the comment
// at its use site in token_cache.go's Token()) and every request would
// refetch from the IdP.
func TestRedisCachingTokenSource_MissingExpiry_AppliesDefaultTTLFallback(t *testing.T) {
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{token: &Token{AccessToken: "no-expiry-token", TokenType: "Bearer"}} // Expiry left zero-value

	const fallbackTTL = 42 * time.Minute
	params := testParams(func(p *oauth2Params) { p.defaultTokenTTL = fallbackTTL })
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), params)

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.Expiry.IsZero() {
		t.Fatal("expected the fallback TTL to give the token a non-zero Expiry")
	}
	wantExpiry := time.Now().Add(fallbackTTL)
	if diff := wantExpiry.Sub(tok.Expiry); diff < -time.Second || diff > time.Second {
		t.Errorf("expected Expiry within 1s of now+%s, got %s away", fallbackTTL, diff)
	}

	key := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(params))
	ttl := rt.client.TTL(context.Background(), key).Val()
	if ttl <= 0 {
		t.Fatalf("expected a positive TTL on the redis key, got %s - the fallback should make this token cacheable", ttl)
	}
	if ttl > fallbackTTL || ttl < fallbackTTL-time.Second {
		t.Errorf("expected redis TTL within 1s of %s, got %s", fallbackTTL, ttl)
	}

	// Second call should be served from the (now-valid) local cache, not
	// trigger a second inner fetch - proving the fallback actually restored
	// caching rather than just avoiding a crash.
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch (second call served from cache), got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_RedisCacheHit_SkipsInnerFetch(t *testing.T) {
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{token: &Token{AccessToken: "should-not-be-used", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	key := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(testParams()))
	cached, _ := json.Marshal(cachedToken{AccessToken: "cached-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)})
	if err := rt.client.Set(context.Background(), key, string(cached), 0).Err(); err != nil {
		t.Fatalf("failed to seed redis: %v", err)
	}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), testParams())

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "cached-token" {
		t.Errorf("expected the redis-cached token to be returned, got %q", tok.AccessToken)
	}
	if inner.calls != 0 {
		t.Errorf("expected 0 inner fetches on a redis cache hit, got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_LocalCache_AvoidsRepeatRedisAndInnerCalls(t *testing.T) {
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{token: &Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), testParams())

	for i := 0; i < 5; i++ {
		if _, err := src.Token(context.Background()); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch across 5 calls (rest served from local cache), got %d", inner.calls)
	}
}

// TestRedisCachingTokenSource_DifferentConfigs_GetIsolatedCacheEntries is the
// regression test for the cross-provider cache collision bug: two policy
// instances backed by different oauth2 credentials (as a proxy's primary
// provider and an additionalProviders entry would be) must never read or
// write each other's Redis entry, even though both may be attached to the
// exact same API.
func TestRedisCachingTokenSource_DifferentConfigs_GetIsolatedCacheEntries(t *testing.T) {
	rt := newTestRedisTarget(t)
	innerA := &stubTokenSource{token: &Token{AccessToken: "token-for-provider-a", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	innerB := &stubTokenSource{token: &Token{AccessToken: "token-for-provider-b", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}

	paramsA := testParams(func(p *oauth2Params) { p.clientID = "provider-a-client" })
	paramsB := testParams(func(p *oauth2Params) { p.clientID = "provider-b-client" })

	srcA := mustNewRedisCachingTokenSource(t, innerA, testRedisParams(rt, FailureModeOpen), paramsA)
	srcB := mustNewRedisCachingTokenSource(t, innerB, testRedisParams(rt, FailureModeOpen), paramsB)

	tokA, err := srcA.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	tokB, err := srcB.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tokA.AccessToken != "token-for-provider-a" {
		t.Errorf("provider A got the wrong token: %q", tokA.AccessToken)
	}
	if tokB.AccessToken != "token-for-provider-b" {
		t.Errorf("provider B got the wrong token: %q", tokB.AccessToken)
	}

	keyA := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(paramsA))
	keyB := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(paramsB))
	if keyA == keyB {
		t.Fatal("expected different oauth2 configs to produce different redis keys")
	}
}

func TestRedisCachingTokenSource_RedisKeyFixedAtConstruction(t *testing.T) {
	// The key is derived from oauth2Params at construction time, not from
	// anything request-time - it never needs to move over the instance's
	// lifetime.
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{token: &Token{AccessToken: "fresh-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	params := testParams()

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), params).(*redisCachingTokenSource)

	want := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(params))
	if src.redisKey != want {
		t.Fatalf("expected redisKey to be set at construction to %q, got %q", want, src.redisKey)
	}

	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if src.redisKey != want {
		t.Errorf("expected the redis key to stay fixed after use, got %q", src.redisKey)
	}
}

func TestRedisCachingTokenSource_RedisDown_FailOpen_FallsBackToInner(t *testing.T) {
	rp := unreachableRedisParams(FailureModeOpen)

	inner := &stubTokenSource{token: &Token{AccessToken: "fallback-token", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, rp, testParams())

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("expected failureMode=open to fall back to the inner source, got error: %v", err)
	}
	if tok.AccessToken != "fallback-token" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected the inner source to be called once as a fallback, got %d", inner.calls)
	}
}

func TestRedisCachingTokenSource_RedisDown_FailClosed_ReturnsErrorWithoutFallback(t *testing.T) {
	rp := unreachableRedisParams(FailureModeClosed)

	inner := &stubTokenSource{token: &Token{AccessToken: "should-not-be-fetched", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, rp, testParams())

	_, err := src.Token(context.Background())
	if err == nil {
		t.Fatal("expected an error when redis is down and failureMode is closed")
	}
	if inner.calls != 0 {
		t.Errorf("expected failureMode=closed to never fall back to the inner source, got %d calls", inner.calls)
	}
}

func TestRedisCachingTokenSource_InnerError_IsPropagated(t *testing.T) {
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{err: errors.New("token endpoint returned invalid_client")}

	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), testParams())

	_, err := src.Token(context.Background())
	if err == nil {
		t.Fatal("expected the inner source's error to propagate")
	}
}

// ─── tokenFreshEnough / expiryBuffer ─────────────────────────────────────────

func TestTokenFreshEnough_Nil_IsNotFresh(t *testing.T) {
	if tokenFreshEnough(nil, time.Minute) {
		t.Error("expected a nil token to never be fresh enough")
	}
}

func TestTokenFreshEnough_EmptyAccessToken_IsNotFresh(t *testing.T) {
	tok := &Token{Expiry: time.Now().Add(time.Hour)}
	if tokenFreshEnough(tok, time.Minute) {
		t.Error("expected a token with no AccessToken to never be fresh enough")
	}
}

func TestTokenFreshEnough_ZeroExpiry_IsFresh(t *testing.T) {
	tok := &Token{AccessToken: "tok"} // Expiry left zero - treated as "never expires"
	if !tokenFreshEnough(tok, time.Minute) {
		t.Error("expected a zero-Expiry token to be treated as fresh")
	}
}

func TestTokenFreshEnough_WithinBuffer_IsNotFresh(t *testing.T) {
	// Expires in 15s; a 30s buffer means this is "not fresh enough" even
	// though the token hasn't actually expired yet.
	tok := &Token{AccessToken: "tok", Expiry: time.Now().Add(15 * time.Second)}
	if tokenFreshEnough(tok, 30*time.Second) {
		t.Error("expected a token expiring within the buffer window to not be fresh enough")
	}
}

func TestTokenFreshEnough_OutsideBuffer_IsFresh(t *testing.T) {
	tok := &Token{AccessToken: "tok", Expiry: time.Now().Add(time.Hour)}
	if !tokenFreshEnough(tok, 30*time.Second) {
		t.Error("expected a token expiring well outside the buffer window to be fresh enough")
	}
}

// TestRedisCachingTokenSource_LocalCache_WithinExpiryBuffer_TriggersRefetch
// locks in that the in-process tier re-fetches once a cached token enters
// its configured expiryBuffer window, rather than serving it until its
// literal expiry - the whole point of the feature (avoid handing the
// backend a credential that's about to expire mid-flight).
func TestRedisCachingTokenSource_LocalCache_WithinExpiryBuffer_TriggersRefetch(t *testing.T) {
	rt := newTestRedisTarget(t)
	inner := &stubTokenSource{token: &Token{AccessToken: "soon-to-expire", TokenType: "Bearer", Expiry: time.Now().Add(5 * time.Second)}}

	params := testParams(func(p *oauth2Params) { p.expiryBuffer = 30 * time.Second })
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), params)

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "soon-to-expire" {
		t.Fatalf("unexpected access token on first call: %q", tok.AccessToken)
	}

	// The just-fetched token's 5s remaining TTL is inside the 30s
	// expiryBuffer, so the next call must not be served from the local
	// cache - it should fall through to a second inner fetch.
	inner.token = &Token{AccessToken: "freshly-refetched", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}
	tok, err = src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if tok.AccessToken != "freshly-refetched" {
		t.Errorf("expected the near-expiry token to trigger a refetch, got access token %q", tok.AccessToken)
	}
	if inner.calls != 2 {
		t.Errorf("expected exactly 2 inner fetches (initial + buffer-triggered refetch), got %d", inner.calls)
	}
}

// TestRedisCachingTokenSource_RedisRead_WithinExpiryBuffer_TriggersRefetch is
// the Redis-tier equivalent: an entry written by another replica that's now
// within this replica's expiryBuffer window must not be served as-is.
func TestRedisCachingTokenSource_RedisRead_WithinExpiryBuffer_TriggersRefetch(t *testing.T) {
	rt := newTestRedisTarget(t)
	params := testParams(func(p *oauth2Params) { p.expiryBuffer = 30 * time.Second })

	key := buildRedisKey(rt.prefix, oauth2ConfigDiscriminator(params))
	cached, _ := json.Marshal(cachedToken{AccessToken: "soon-to-expire", TokenType: "Bearer", Expiry: time.Now().Add(5 * time.Second)})
	if err := rt.client.Set(context.Background(), key, string(cached), 0).Err(); err != nil {
		t.Fatalf("failed to seed redis: %v", err)
	}

	inner := &stubTokenSource{token: &Token{AccessToken: "freshly-refetched", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), params)

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "freshly-refetched" {
		t.Errorf("expected the near-expiry redis entry to be rejected and trigger a refetch, got access token %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly 1 inner fetch after rejecting the stale redis entry, got %d", inner.calls)
	}
}

// TestBuildTokenSource_ClientCredentials_ExpiryBuffer_ForcesRealRefetch is
// the end-to-end regression test confirming buildTokenSource's real
// construction path (not stubTokenSource) actually threads expiryBuffer
// into reuseTokenSource, rather than some hardcoded margin - a fixed,
// non-configurable buffer would keep silently handing back the same
// soon-to-expire token whenever the outer cache's larger expiryBuffer
// decided to fall through and re-fetch. Uses a real httptest server so the
// full path, not a stub, is what's actually exercised.
func TestBuildTokenSource_ClientCredentials_ExpiryBuffer_ForcesRealRefetch(t *testing.T) {
	rt := newTestRedisTarget(t)

	var idpCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpCalls++
		accessToken, expiresIn := "token-1", 5 // expires in 5s - inside the 10s expiryBuffer below
		if idpCalls > 1 {
			accessToken, expiresIn = "token-2", 300
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		})
	}))
	defer server.Close()

	params := testParams(func(p *oauth2Params) {
		p.tokenEndpoint = server.URL
		p.expiryBuffer = 10 * time.Second
	})
	inner, err := buildTokenSource(params)
	if err != nil {
		t.Fatalf("unexpected error building token source: %v", err)
	}
	src := mustNewRedisCachingTokenSource(t, inner, testRedisParams(rt, FailureModeOpen), params)

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error priming the cache: %v", err)
	}
	if tok.AccessToken != "token-1" {
		t.Fatalf("unexpected primed access token: %q", tok.AccessToken)
	}
	if idpCalls != 1 {
		t.Fatalf("expected exactly 1 token-endpoint call to prime the cache, got %d", idpCalls)
	}

	// token-1's 5s remaining TTL is inside the 10s expiryBuffer: the outer
	// cache falls through to inner.Token(context.Background()), and inner itself - via
	// reuseTokenSource using that same 10s buffer - must perform a genuine
	// second token-endpoint call rather than replaying token-1.
	tok, err = src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "token-2" {
		t.Errorf("expected expiryBuffer to force a fresh token-endpoint call instead of reusing the near-expiry token, got access token %q", tok.AccessToken)
	}
	if idpCalls != 2 {
		t.Errorf("expected exactly 2 token-endpoint calls total (primed + buffer-triggered refetch), got %d", idpCalls)
	}
}

// ─── getOrCreateRedisClient ──────────────────────────────────────────────────

func TestGetOrCreateRedisClient_SharesClientForIdenticalConfig(t *testing.T) {
	rt := newTestRedisTarget(t)
	rp := testRedisParams(rt, FailureModeOpen)

	src1 := mustNewRedisCachingTokenSource(t, &stubTokenSource{}, rp, testParams()).(*redisCachingTokenSource)
	src2 := mustNewRedisCachingTokenSource(t, &stubTokenSource{}, rp, testParams()).(*redisCachingTokenSource)

	if src1.redisClient != src2.redisClient {
		t.Error("expected two policy instances with identical redis connection settings to share one *redis.Client")
	}
}

// ─── keyedSingleton ───────────────────────────────────────────────────────────

func TestKeyedSingleton_SecondCallForSameKeyReusesFirstValue(t *testing.T) {
	r := newKeyedSingleton[string, *int]()
	var builds int32

	build := func() (*int, error) {
		atomic.AddInt32(&builds, 1)
		v := 42
		return &v, nil
	}

	v1, created1, err := r.getOrCreate("a", build)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !created1 {
		t.Error("expected the first call for a new key to report created=true")
	}

	v2, created2, err := r.getOrCreate("a", build)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created2 {
		t.Error("expected the second call for the same key to report created=false")
	}
	if v1 != v2 {
		t.Error("expected the second call to reuse the exact same value, not build a new one")
	}
	if builds != 1 {
		t.Errorf("expected build to run exactly once, got %d", builds)
	}
}

func TestKeyedSingleton_DifferentKeysBuildIndependently(t *testing.T) {
	r := newKeyedSingleton[string, string]()

	va, _, err := r.getOrCreate("a", func() (string, error) { return "value-a", nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	vb, _, err := r.getOrCreate("b", func() (string, error) { return "value-b", nil })
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if va != "value-a" || vb != "value-b" {
		t.Errorf("expected independent values per key, got %q and %q", va, vb)
	}
}

func TestKeyedSingleton_FailedBuildIsNotCached(t *testing.T) {
	r := newKeyedSingleton[string, string]()
	wantErr := errors.New("build failed")

	_, created, err := r.getOrCreate("a", func() (string, error) { return "", wantErr })
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected the build error to be returned, got %v", err)
	}
	if created {
		t.Error("expected created=false on a failed build")
	}

	// A retry for the same key must attempt to build again, not serve a
	// cached empty value from the failed attempt.
	v, created, err := r.getOrCreate("a", func() (string, error) { return "value-a", nil })
	if err != nil {
		t.Fatalf("unexpected error on retry: %v", err)
	}
	if !created {
		t.Error("expected the retry to report created=true - a failed build must not have been cached")
	}
	if v != "value-a" {
		t.Errorf("expected the retry's value to be returned, got %q", v)
	}
}

// TestKeyedSingleton_ConcurrentBuildsForSameKey_AllCallersSeeOneWinner locks
// in getOrCreate's documented race resolution: when multiple callers race to
// build the same not-yet-cached key, build may run more than once, but every
// caller ends up observing the exact same single winning value - never a
// mix of different pointers for what should be one shared singleton.
func TestKeyedSingleton_ConcurrentBuildsForSameKey_AllCallersSeeOneWinner(t *testing.T) {
	r := newKeyedSingleton[string, *int]()

	const n = 50
	results := make([]*int, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			v, _, err := r.getOrCreate("shared", func() (*int, error) {
				val := 1
				return &val, nil
			})
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			results[i] = v
		}(i)
	}
	wg.Wait()

	first := results[0]
	for i, v := range results {
		if v != first {
			t.Errorf("caller %d observed a different value pointer than caller 0 - not a single shared singleton", i)
		}
	}
}

func TestNewRedisCachingTokenSource_MemoryStrategy_NeverTouchesRedis(t *testing.T) {
	cp := cacheParams{
		strategy: CacheStrategyMemory,
		redis: redisParams{
			// Deliberately unreachable - if cacheStrategy: memory ever
			// dialed Redis despite the strategy, using this host would
			// surface as an error or a fallback rather than silently
			// succeeding via the in-process tier alone.
			host:              "unreachable.invalid",
			port:              1,
			connectionTimeout: 50 * time.Millisecond,
			readTimeout:       50 * time.Millisecond,
			writeTimeout:      50 * time.Millisecond,
		},
	}
	inner := &stubTokenSource{token: &Token{AccessToken: "tok", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour)}}
	src := mustNewRedisCachingTokenSource(t, inner, cp, testParams()).(*redisCachingTokenSource)

	if src.redisClient != nil {
		t.Fatal("expected cacheStrategy: memory to never construct a redis client")
	}

	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error with an unreachable redis host configured under memory strategy: %v", err)
	}
	if tok.AccessToken != "tok" {
		t.Errorf("unexpected access token: %q", tok.AccessToken)
	}
	if inner.calls != 1 {
		t.Errorf("expected exactly one inner fetch, got %d", inner.calls)
	}

	// Second call should be served from the in-process tier without
	// refetching - the only tier active under memory strategy.
	if _, err := src.Token(context.Background()); err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if inner.calls != 1 {
		t.Errorf("expected the in-process cache to avoid a second inner fetch, got %d calls", inner.calls)
	}
}

// ─── extractCacheParams ──────────────────────────────────────────────────────

func TestExtractCacheParams_DefaultsWhenAbsent(t *testing.T) {
	cp := extractCacheParams(map[string]interface{}{})
	if cp.strategy != CacheStrategyMemory {
		t.Errorf("expected cacheStrategy to default to %q, got %q", CacheStrategyMemory, cp.strategy)
	}
	rp := cp.redis
	if rp.host != defaultRedisHost || rp.port != defaultRedisPort || rp.keyPrefix != defaultRedisKeyPrefix || rp.failureMode != FailureModeOpen {
		t.Errorf("unexpected redis defaults: %+v", rp)
	}
}

func TestExtractCacheParams_StrategyRedis(t *testing.T) {
	params := map[string]interface{}{
		"cacheStrategy": "redis",
	}
	cp := extractCacheParams(params)
	if cp.strategy != CacheStrategyRedis {
		t.Errorf("expected cacheStrategy %q, got %q", CacheStrategyRedis, cp.strategy)
	}
}

func TestExtractCacheParams_NestedMapShape(t *testing.T) {
	params := map[string]interface{}{
		"cacheStrategy": "redis",
		"redis": map[string]interface{}{
			"host":        "redis.internal",
			"port":        float64(6380), // JSON numbers decode as float64
			"keyPrefix":   "custom:",
			"failureMode": "closed",
		},
	}
	cp := extractCacheParams(params)
	rp := cp.redis
	if rp.host != "redis.internal" || rp.port != 6380 || rp.keyPrefix != "custom:" || rp.failureMode != "closed" {
		t.Errorf("unexpected params from nested map shape: %+v", rp)
	}
}

func TestExtractCacheParams_FlattenedDottedKeyShape(t *testing.T) {
	params := map[string]interface{}{
		"cacheStrategy": "redis",
		"redis.host":    "redis.internal",
		"redis.port":    6380,
	}
	cp := extractCacheParams(params)
	if cp.strategy != CacheStrategyRedis {
		t.Errorf("expected cacheStrategy %q, got %q", CacheStrategyRedis, cp.strategy)
	}
	if cp.redis.host != "redis.internal" || cp.redis.port != 6380 {
		t.Errorf("unexpected params from flattened dotted-key shape: %+v", cp.redis)
	}
}

func TestExtractCacheParams_DurationParsing(t *testing.T) {
	params := map[string]interface{}{
		"redis": map[string]interface{}{
			"connectionTimeout": "250ms",
		},
	}
	cp := extractCacheParams(params)
	if cp.redis.connectionTimeout != 250*time.Millisecond {
		t.Errorf("expected 250ms connectionTimeout, got %v", cp.redis.connectionTimeout)
	}
}

// TestExtractCacheParams_NonPositiveTimeouts_FallBackToDefault locks in that
// a zero or negative redis.connectionTimeout/readTimeout/writeTimeout falls
// back to its default rather than being honored as-is - handing
// context.WithTimeout a <= 0 duration produces an already-expired deadline,
// making every Redis operation fail instantly regardless of Redis's actual
// health (see oauth2_generator_test.go's identical concern for
// tokenRequestTimeout/defaultTokenTTL).
func TestExtractCacheParams_NonPositiveTimeouts_FallBackToDefault(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
	}{
		{"zero", "0s"},
		{"negative", "-1s"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params := map[string]interface{}{
				"redis": map[string]interface{}{
					"connectionTimeout": tt.value,
					"readTimeout":       tt.value,
					"writeTimeout":      tt.value,
				},
			}
			cp := extractCacheParams(params)
			if cp.redis.connectionTimeout != defaultRedisConnectionTimeout {
				t.Errorf("expected non-positive connectionTimeout %q to fall back to default %s, got %s",
					tt.value, defaultRedisConnectionTimeout, cp.redis.connectionTimeout)
			}
			if cp.redis.readTimeout != defaultRedisReadTimeout {
				t.Errorf("expected non-positive readTimeout %q to fall back to default %s, got %s",
					tt.value, defaultRedisReadTimeout, cp.redis.readTimeout)
			}
			if cp.redis.writeTimeout != defaultRedisWriteTimeout {
				t.Errorf("expected non-positive writeTimeout %q to fall back to default %s, got %s",
					tt.value, defaultRedisWriteTimeout, cp.redis.writeTimeout)
			}
		})
	}
}
