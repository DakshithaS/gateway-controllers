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
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// defaultTokenRequestTimeout bounds how long a single token-endpoint
	// HTTP call is allowed to take, via the *http.Client we build ourselves
	// (see buildTokenSource) - a hung IdP must not block a token fetch
	// indefinitely.
	defaultTokenRequestTimeout = 10 * time.Second

	// defaultTokenTTLFallback is applied when the token endpoint's response
	// omits expires_in - without this, a token with a zero Expiry would
	// never be treated as cacheable (see tokenFreshEnough).
	defaultTokenTTLFallback = time.Hour

	// defaultHeaderName is the header the generated credential is injected
	// into when headerName is omitted.
	defaultHeaderName = "Authorization"

	// defaultValuePrefix is prepended (followed by a single space) to the
	// credential value when valuePrefix is omitted. An explicitly configured
	// empty string is honored as "no prefix" rather than falling back to
	// this - see getStringParamOrDefault.
	defaultValuePrefix = "Bearer"

	// defaultTokenRequestMaxRetries bounds how many additional attempts
	// resilientTokenSource makes after the initial token-endpoint call
	// fails with a transient error - see isRetryableTokenError.
	defaultTokenRequestMaxRetries = 2

	// retryBaseDelay/retryMaxDelay bound resilientTokenSource's backoff
	// between attempts - exponential from retryBaseDelay, capped at
	// retryMaxDelay, with up to 50% jitter to avoid every replica retrying
	// in lockstep against the same struggling identity provider.
	retryBaseDelay = 100 * time.Millisecond
	retryMaxDelay  = 2 * time.Second

	// defaultExpiryBuffer is how far ahead of a token's actual expiry it's
	// treated as no-longer-fresh, both by the caching layer (token_cache.go's
	// tokenFreshEnough) and by the token-endpoint source itself (via
	// reuseTokenSource below) - see expiryBuffer's field comment. 30s
	// comfortably covers a request's own in-flight time to the backend.
	defaultExpiryBuffer = 30 * time.Second

	// maxTokenResponseBytes bounds how much of a token-endpoint response
	// body is read, regardless of what the server claims via
	// Content-Length - a misbehaving IdP must not be able to exhaust memory
	// via an oversized response (see file-access.md's stream-limit
	// directive). Token responses are always small; this is generous.
	maxTokenResponseBytes = 1 << 20 // 1MiB
)

// defaultPurgeStatusCodes is applied when tokenPurgeStatusCodes is
// omitted. 401 is the standard signal (RFC 6750 Section 3) that a bearer
// token was rejected as invalid - as opposed to e.g. 403, which usually
// means insufficient scope for an otherwise-valid token and would gain
// nothing from a purge.
var defaultPurgeStatusCodes = []int{http.StatusUnauthorized}

const (
	// GrantTypeClientCredentials (RFC 6749 Section 4.4) is the standard
	// machine-to-machine grant and should be preferred whenever the
	// upstream identity provider supports it.
	GrantTypeClientCredentials = "client_credentials"

	// GrantTypePassword (RFC 6749 Section 4.3) bridges legacy IdPs that only
	// expose this grant - discouraged for new integrations since it requires
	// handling the resource owner's raw credentials directly.
	GrantTypePassword = "password"

	// AuthType is the AuthContext.AuthType for the token-endpoint path. The
	// specific grant is available separately via Properties["grantType"].
	AuthType = "oauth2"

	// AuthTypeStaticToken is the AuthContext.AuthType for the
	// directly-supplied-token path - no OAuth2 grant involved.
	AuthTypeStaticToken = "static-token"

	// ModeTokenEndpoint and ModeStaticToken identify which mutually exclusive
	// auth path a policy instance was configured for.
	ModeTokenEndpoint = "token-endpoint"
	ModeStaticToken   = "static-token"

	// ClientAuthMethodBasic (client_secret_basic) sends client ID/secret via HTTP
	// Basic auth - RFC 6749's preferred convention, and this policy's default.
	ClientAuthMethodBasic = "client_secret_basic"

	// ClientAuthMethodPost (client_secret_post) sends client ID/secret as form
	// fields instead of the Basic header.
	ClientAuthMethodPost = "client_secret_post"
)

// Token is the subset of an RFC 6749 §5.1 token response this policy needs.
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Expiry       time.Time
}

// TokenSource supplies the current access token, fetching or reusing a
// cached one as it sees fit - satisfied by tokenFetcherFunc,
// reuseTokenSource, resilientTokenSource, and redisCachingTokenSource
// (token_cache.go).
type TokenSource interface {
	Token() (*Token, error)
}

// TokenError represents an RFC 6749 §5.2 error response FROM the token
// endpoint - the request reached the IdP and was explicitly rejected, as
// opposed to a network-level failure (DNS, connection refused, timeout)
// that never got a response at all, or a malformed 200 response (see
// doTokenRequest's missing-access_token check, deliberately a plain error
// instead of *TokenError - retrying a malformed-but-200 response is exactly
// as likely to help as retrying anything else transient).
type TokenError struct {
	StatusCode       int
	ErrorCode        string
	ErrorDescription string
}

func (e *TokenError) Error() string {
	switch {
	case e.ErrorDescription != "":
		return fmt.Sprintf("token endpoint returned %d %s: %s", e.StatusCode, e.ErrorCode, e.ErrorDescription)
	case e.ErrorCode != "":
		return fmt.Sprintf("token endpoint returned %d %s", e.StatusCode, e.ErrorCode)
	default:
		return fmt.Sprintf("token endpoint returned status %d", e.StatusCode)
	}
}

// clientAuthStyle mirrors clientAuthMethod as a type doTokenRequest can
// switch on - see authStyleFor.
type clientAuthStyle int

const (
	authStyleInHeader  clientAuthStyle = iota // client_secret_basic: HTTP Basic auth
	authStyleInParams                         // client_secret_post: client_id/client_secret as form fields
)

// authStyleFor maps clientAuthMethod to the style doTokenRequest consumes.
// validateAndExtractParams already rejects any other value, so the default
// case covers only ClientAuthMethodBasic.
func authStyleFor(method string) clientAuthStyle {
	if method == ClientAuthMethodPost {
		return authStyleInParams
	}
	return authStyleInHeader
}

// tokenJSON is the raw shape of an RFC 6749 §5.1 token response.
// ExpiresIn is left as json.RawMessage rather than int64 because some IdPs
// send it as a JSON string instead of a number - see expiresInSeconds.
type tokenJSON struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	RefreshToken string          `json:"refresh_token"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
}

func (t tokenJSON) expiresInSeconds() (int64, bool) {
	if len(t.ExpiresIn) == 0 {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(t.ExpiresIn, &n); err == nil {
		return n, true
	}
	var s string
	if err := json.Unmarshal(t.ExpiresIn, &s); err == nil {
		if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

// doTokenRequest POSTs form to tokenEndpoint (RFC 6749 §4.3/§4.4's shared
// wire shape) and parses the response. style selects how the client
// authenticates: authStyleInHeader adds an HTTP Basic header (RFC 6749
// Appendix B - client_id/client_secret are form-urlencoded BEFORE being
// combined into the Basic credential, so a raw base64(id+":"+secret)
// would mishandle any id/secret containing a colon or other reserved
// character); authStyleInParams instead adds client_id/client_secret
// directly to form. extraHeaders is applied last, skipping
// Authorization/Content-Type so it can never override the client-auth or
// body-encoding headers set above.
func doTokenRequest(ctx context.Context, httpClient *http.Client, tokenEndpoint string, style clientAuthStyle,
	clientID, clientSecret string, form url.Values, extraHeaders map[string]string) (*Token, error) {
	if style == authStyleInParams {
		form.Set("client_id", clientID)
		form.Set("client_secret", clientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	for k, v := range extraHeaders {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Content-Type") {
			continue
		}
		req.Header.Set(k, v)
	}
	if style == authStyleInHeader {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}
	if len(body) > maxTokenResponseBytes {
		return nil, fmt.Errorf("token response exceeded %d bytes", maxTokenResponseBytes)
	}

	if resp.StatusCode != http.StatusOK {
		tokErr := &TokenError{StatusCode: resp.StatusCode}
		var errBody struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(body, &errBody) == nil {
			tokErr.ErrorCode = errBody.Error
			tokErr.ErrorDescription = errBody.ErrorDescription
		}
		return nil, tokErr
	}

	var parsed tokenJSON
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("token endpoint response is missing access_token")
	}

	tok := &Token{
		AccessToken:  parsed.AccessToken,
		TokenType:    parsed.TokenType,
		RefreshToken: parsed.RefreshToken,
	}
	if tok.TokenType == "" {
		tok.TokenType = "Bearer"
	}
	if secs, ok := parsed.expiresInSeconds(); ok {
		tok.Expiry = time.Now().Add(time.Duration(secs) * time.Second)
	}
	return tok, nil
}

// fetchClientCredentialsToken implements RFC 6749 §4.4. tokenRequestParams
// (e.g. scope, audience) is forwarded verbatim into the request body.
func fetchClientCredentialsToken(ctx context.Context, httpClient *http.Client, p oauth2Params, style clientAuthStyle) (*Token, error) {
	form := toURLValues(p.tokenRequestParams)
	if form == nil {
		form = url.Values{}
	}
	form.Set("grant_type", GrantTypeClientCredentials)
	return doTokenRequest(ctx, httpClient, p.tokenEndpoint, style, p.clientID, p.clientSecret, form, p.tokenRequestHeaders)
}

// fetchPasswordToken implements the Resource Owner Password Credentials
// grant (RFC 6749 §4.3). scope is the only tokenRequestParams entry this
// grant honors - space-delimited per RFC 6749 §3.3; everything else
// (audience, resource, ...) has no effect, matching client_credentials'
// EndpointParams-equivalent but restricted to what this grant actually
// supports.
func fetchPasswordToken(ctx context.Context, httpClient *http.Client, p oauth2Params, style clientAuthStyle) (*Token, error) {
	form := url.Values{}
	form.Set("grant_type", GrantTypePassword)
	form.Set("username", p.username)
	form.Set("password", p.password)
	if scope := strings.Fields(p.tokenRequestParams["scope"]); len(scope) > 0 {
		form.Set("scope", strings.Join(scope, " "))
	}
	return doTokenRequest(ctx, httpClient, p.tokenEndpoint, style, p.clientID, p.clientSecret, form, p.tokenRequestHeaders)
}

// tokenFetcherFunc adapts a plain fetch function to TokenSource - see
// buildTokenSource.
type tokenFetcherFunc func() (*Token, error)

func (f tokenFetcherFunc) Token() (*Token, error) { return f() }

// reuseTokenSource wraps a raw, IdP-fetching TokenSource with mutex-guarded
// reuse: the same token is served on every call until it's within buffer of
// its own expiry, at which point the next caller performs a single
// refetch while holding the lock - every other concurrent caller queues
// behind that same mutex rather than firing a duplicate request, and sees
// the now-fresh token once it's released. Mirrors
// golang.org/x/oauth2's own reuseTokenSource, with our own configurable
// buffer instead of its hardcoded, non-configurable 10s one - see
// oauth2Params.expiryBuffer's field comment for why this must match the
// caching layer's own threshold.
type reuseTokenSource struct {
	mu     sync.Mutex
	fresh  TokenSource
	tok    *Token
	buffer time.Duration
}

func newReuseTokenSource(fresh TokenSource, buffer time.Duration) *reuseTokenSource {
	return &reuseTokenSource{fresh: fresh, buffer: buffer}
}

func (s *reuseTokenSource) Token() (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tokenFreshEnough(s.tok, s.buffer) {
		return s.tok, nil
	}
	tok, err := s.fresh.Token()
	if err != nil {
		return nil, err
	}
	s.tok = tok
	return tok, nil
}

// oauth2Params bundles all extracted, validated policy params. Passed as a
// single struct (rather than positional args) now that the set has grown
// with grantType-conditional fields (username/password) — positional args
// for six-plus mostly-string fields invite mixed-up-order bugs.
type oauth2Params struct {
	// bearerToken is the directly-supplied credential for the static-token
	// auth path. Non-empty here means the whole token-endpoint block below
	// is unused - see validateAndExtractParams for the mutual-exclusion
	// check.
	bearerToken string

	grantType        string
	tokenEndpoint    string
	clientID         string
	clientSecret     string
	clientAuthMethod string
	username         string
	password         string

	// For client_credentials, tokenRequestParams carries the whole map into the
	// token request body. For password, only "scope" has any effect - see
	// fetchClientCredentialsToken/fetchPasswordToken.
	tokenRequestParams map[string]string

	// Extra HTTP headers sent with the token-endpoint request, on top of
	// clientAuthMethod/the grant's own headers. "Authorization"/"Content-Type"
	// are dropped rather than honored - see doTokenRequest.
	tokenRequestHeaders map[string]string

	// requestTimeout bounds the token-endpoint HTTP call - see
	// defaultTokenRequestTimeout.
	requestTimeout time.Duration

	// tokenTTLFallback is applied by the caching layer when the token
	// endpoint's response omits expires_in - see defaultTokenTTLFallback.
	tokenTTLFallback time.Duration

	// expiryBuffer is how far ahead of a token's actual expiry it's treated
	// as stale, so a request never gets sent upstream with a credential that
	// expires mid-flight or a hair before the backend even sees it. Applied
	// both to the caching layer's own local/Redis freshness check
	// (token_cache.go's tokenFreshEnough) and to the token-endpoint source's
	// own reuse behavior (see buildTokenSource's use of reuseTokenSource) -
	// both must agree on the same threshold, or the cache layer would decide
	// a token is stale while the token source itself still considers its own
	// cached copy fresh and hands back the very token being avoided. Unused
	// when bearerToken is set - see defaultExpiryBuffer.
	expiryBuffer time.Duration

	// purgeStatusCodes are the upstream response status codes that purge the
	// cached token - see OnResponseHeaders and defaultPurgeStatusCodes.
	// Forced empty by GetPolicy when bearerToken is set - see its comment.
	purgeStatusCodes map[int]struct{}

	// headerName and valuePrefix control where and how the credential
	// (fetched or directly-supplied) is injected - see buildHeaderValue.
	// Apply identically to both auth paths.
	headerName  string
	valuePrefix string

	// proxyURL/tlsCaCertPath/tlsInsecureSkipVerify configure the
	// token-endpoint HTTP client's Transport - see
	// buildTokenEndpointTransport. Unused when bearerToken is set.
	proxyURL              string
	tlsCaCertPath         string
	tlsInsecureSkipVerify bool

	// tokenRequestMaxRetries bounds resilientTokenSource's retry of the
	// token-endpoint fetch - see defaultTokenRequestMaxRetries. Unused when
	// bearerToken is set.
	tokenRequestMaxRetries int
}

// mode reports which of the two mutually exclusive auth paths p represents -
// see ModeTokenEndpoint/ModeStaticToken.
func (p oauth2Params) mode() string {
	if p.bearerToken != "" {
		return ModeStaticToken
	}
	return ModeTokenEndpoint
}

// Policy generates an upstream credential - either fetched via an OAuth2 grant
// (client_credentials or password) or a directly-supplied static one - and
// injects it into a configurable request header before forwarding.
type Policy struct {
	// mode records which of the two mutually exclusive auth paths this
	// instance was configured for - see ModeTokenEndpoint/ModeStaticToken.
	mode string

	grantType        string
	tokenEndpoint    string
	clientID         string
	clientAuthMethod string

	// headerName and valuePrefix control where and how the credential is
	// injected - see buildHeaderValue.
	headerName  string
	valuePrefix string

	// tokenSource supplies the credential to inject: a *redisCachingTokenSource
	// (token_cache.go) for the token-endpoint path, or a *staticTokenSource that
	// always returns the configured token as-is.
	tokenSource tokenProvider

	// Test seam — production code calls tokenSource.Token() directly; unit
	// tests override this to avoid a real network call to a token endpoint,
	// mirroring the retrieveCredentialsFunc pattern used in the
	// aws-authentication policy.
	tokenFunc func() (*Token, error)

	// purgeStatusCodes are the upstream response status codes that purge the
	// cached token via tokenSource.Purge() - see OnResponseHeaders. Empty
	// (explicitly set to [], or always for the static-token path - see
	// GetPolicy) disables response-phase processing entirely - see Mode().
	purgeStatusCodes map[int]struct{}
}

// staticTokenSource always returns the same configured token, no endpoint call or
// caching involved. Expiry is left at its zero value deliberately - tokenFreshEnough
// treats that as "never expires", right for a credential with no expiry of its own.
// Purge is a no-op: nothing cached to clear, no fresher token to fetch.
type staticTokenSource struct {
	bearerToken string
}

func (s *staticTokenSource) Token() (*Token, error) {
	return &Token{AccessToken: s.bearerToken, TokenType: "Bearer"}, nil
}

func (s *staticTokenSource) Purge() {}

// buildHeaderValue combines valuePrefix and the credential into the header
// value to inject - e.g. buildHeaderValue("Bearer", "abc") -> "Bearer abc".
// An empty prefix (explicitly configured - see getStringParamOrDefault)
// yields the raw credential with no scheme prefix.
func buildHeaderValue(prefix, token string) string {
	if prefix == "" {
		return token
	}
	return prefix + " " + token
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
// metadata is part of the v1alpha2 factory signature but unused here: the
// Redis cache key is derived entirely from params (see
// oauth2ConfigDiscriminator in token_cache.go).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	slog.Debug("OAuth2Generator: constructing policy from params")

	p, err := validateAndExtractParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid params: %w", err)
	}
	mode := p.mode()
	slog.Debug("OAuth2Generator: validated params", "mode", mode,
		"grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID,
		"clientAuthMethod", p.clientAuthMethod, "headerName", p.headerName)

	var tokenSource tokenProvider
	if mode == ModeStaticToken {
		// Nothing to fetch or cache - the configured token is injected as-is
		// on every request. Also force purgeStatusCodes off: there is no
		// fresher token to fetch on a rejection, and leaving it configured
		// would otherwise turn on response-header processing (see Mode())
		// for a purge that Purge() no-ops anyway.
		tokenSource = &staticTokenSource{bearerToken: p.bearerToken}
		p.purgeStatusCodes = map[int]struct{}{}
	} else {
		innerSource, err := buildTokenSource(p)
		if err != nil {
			return nil, err
		}
		tokenSource = newRedisCachingTokenSource(innerSource, extractCacheParams(params), p)
	}

	pol := &Policy{
		mode:             mode,
		grantType:        p.grantType,
		tokenEndpoint:    p.tokenEndpoint,
		clientID:         p.clientID,
		clientAuthMethod: p.clientAuthMethod,
		headerName:       p.headerName,
		valuePrefix:      p.valuePrefix,
		tokenSource:      tokenSource,
		purgeStatusCodes: p.purgeStatusCodes,
	}
	pol.tokenFunc = pol.tokenSource.Token

	slog.Debug("OAuth2Generator: policy initialized", "mode", pol.mode,
		"grantType", pol.grantType, "tokenEndpoint", pol.tokenEndpoint, "clientId", pol.clientID,
		"clientAuthMethod", pol.clientAuthMethod, "headerName", pol.headerName)

	return pol, nil
}

// buildTokenSource constructs the token source for the given grantType,
// wrapping the raw HTTP-fetching function (fetchClientCredentialsToken/
// fetchPasswordToken) in reuseTokenSource for mutex-safe caching. This is
// the extension point for future grants: each grant gets its own case here.
func buildTokenSource(p oauth2Params) (TokenSource, error) {
	style := authStyleFor(p.clientAuthMethod)

	// The Transport itself is shared across policy instances/rebuilds - see
	// getOrCreateTokenEndpointTransport. The *http.Client (and its Timeout)
	// is rebuilt here each time, which is cheap - only the Transport (and
	// its connection pool) needs to be shared.
	transport, err := getOrCreateTokenEndpointTransport(p)
	if err != nil {
		return nil, fmt.Errorf("invalid token endpoint transport config: %w", err)
	}
	httpClient := &http.Client{Timeout: p.requestTimeout, Transport: transport}

	switch p.grantType {
	case GrantTypeClientCredentials:
		raw := tokenFetcherFunc(func() (*Token, error) {
			return fetchClientCredentialsToken(context.Background(), httpClient, p, style)
		})
		return newReuseTokenSource(raw, p.expiryBuffer), nil

	case GrantTypePassword:
		raw := tokenFetcherFunc(func() (*Token, error) {
			return fetchPasswordToken(context.Background(), httpClient, p, style)
		})
		return newReuseTokenSource(raw, p.expiryBuffer), nil

	default:
		// Unreachable - validateAndExtractParams already rejects any other
		// value - kept as an explicit guard for a future added grant.
		return nil, fmt.Errorf("unsupported grantType %q", p.grantType)
	}
}

// tokenEndpointTransportKey identifies a distinct token-endpoint HTTP
// client configuration. tlsCACertHash hashes the CA cert's CONTENT, not its
// path - a cert rotated at the same path (e.g. a regenerated self-signed
// test cert) would otherwise keep validating against a stale cached pool
// (TESTING.md E.27).
type tokenEndpointTransportKey struct {
	proxyURL              string
	tlsCACertHash         string
	tlsInsecureSkipVerify bool
}

// tokenEndpointTransports is the process-wide registry of shared *http.Transport
// values for the token-endpoint HTTP client, keyed by proxy/TLS configuration -
// mirrors redisClients (redis_clients.go), for the same connection-pool-fragmentation
// reason.
var tokenEndpointTransports = struct {
	mu sync.Mutex
	m  map[tokenEndpointTransportKey]*http.Transport
}{m: make(map[tokenEndpointTransportKey]*http.Transport)}

// getOrCreateTokenEndpointTransport returns the process-wide shared
// Transport for this proxy/TLS configuration, building it on first use. The
// CA cert is read here for the cache key, then again in
// buildTokenEndpointTransport on a cache miss.
func getOrCreateTokenEndpointTransport(p oauth2Params) (*http.Transport, error) {
	certHash, err := hashCACertFile(p.tlsCaCertPath)
	if err != nil {
		return nil, fmt.Errorf("tlsCaCertPath: %w", err)
	}

	key := tokenEndpointTransportKey{
		proxyURL:              p.proxyURL,
		tlsCACertHash:         certHash,
		tlsInsecureSkipVerify: p.tlsInsecureSkipVerify,
	}

	tokenEndpointTransports.mu.Lock()
	defer tokenEndpointTransports.mu.Unlock()

	if t, ok := tokenEndpointTransports.m[key]; ok {
		return t, nil
	}

	t, err := buildTokenEndpointTransport(p)
	if err != nil {
		return nil, err
	}
	tokenEndpointTransports.m[key] = t
	return t, nil
}

// hashCACertFile returns a hex sha256 of the file's content, or "" when
// path is empty.
func hashCACertFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read CA cert file %q: %w", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// buildTokenEndpointTransport wires proxyURL and TLS settings into one Transport
// deliberately, setting Proxy explicitly alongside TLSClientConfig: an unset
// Transport.Proxy means "never proxy" (it does NOT inherit ProxyFromEnvironment) -
// exactly how jwt-auth and opaque-token-auth each lost proxy support the moment a
// custom TLS config was added, by setting only one of the two.
func buildTokenEndpointTransport(p oauth2Params) (*http.Transport, error) {
	proxyFunc := http.ProxyFromEnvironment
	if p.proxyURL != "" {
		proxyURL, err := url.Parse(p.proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxyURL: %w", err)
		}
		proxyFunc = http.ProxyURL(proxyURL)
	}

	transport := &http.Transport{Proxy: proxyFunc}

	if p.tlsCaCertPath != "" || p.tlsInsecureSkipVerify {
		tlsConfig := &tls.Config{InsecureSkipVerify: p.tlsInsecureSkipVerify} //nolint:gosec // opt-in, logged at extraction time
		if p.tlsCaCertPath != "" {
			pool, err := loadCACertPool(p.tlsCaCertPath)
			if err != nil {
				return nil, fmt.Errorf("tlsCaCertPath: %w", err)
			}
			tlsConfig.RootCAs = pool
		}
		transport.TLSClientConfig = tlsConfig
	}

	return transport, nil
}

// loadCACertPool reads a PEM-encoded CA certificate file and returns a pool
// containing it, for TLS connections that must trust a private/internal CA
// - used by buildTokenEndpointTransport above, its only caller.
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

// resilientTokenSource wraps a real, IDP-fetching TokenSource with bounded
// retry, for transient failures only - see isRetryableTokenError.
type resilientTokenSource struct {
	inner      TokenSource
	maxRetries int
}

func (r *resilientTokenSource) Token() (*Token, error) {
	var lastErr error
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(retryBackoff(attempt))
		}
		tok, err := r.inner.Token()
		if err == nil {
			return tok, nil
		}
		lastErr = err
		if !isRetryableTokenError(err) {
			return nil, err
		}
	}
	return nil, lastErr
}

// isRetryableTokenError classifies a token-fetch error as worth retrying. A
// *TokenError is only retryable on 429/5xx - a 4xx like invalid_client is a
// rejected request retrying can't fix. Any other error (DNS, connection
// refused, TLS, deadline exceeded, or a malformed-but-200 response - see
// doTokenRequest) never got a definitive rejection FROM the IdP, so it's
// treated as transient.
func isRetryableTokenError(err error) bool {
	var tokErr *TokenError
	if errors.As(err, &tokErr) {
		return tokErr.StatusCode == http.StatusTooManyRequests || tokErr.StatusCode >= 500
	}
	return true
}

// retryBackoff returns the delay before retry attempt n (n >= 1):
// exponential from retryBaseDelay, capped at retryMaxDelay, plus up to 50%
// jitter so that many gateway-runtime replicas whose tokens expire around
// the same time don't all retry against a struggling identity provider in
// lockstep.
func retryBackoff(attempt int) time.Duration {
	backoff := retryBaseDelay * time.Duration(uint64(1)<<uint(attempt-1))
	if backoff > retryMaxDelay || backoff <= 0 {
		backoff = retryMaxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(backoff)/2 + 1))
	return backoff + jitter
}

// toURLValues converts a flat string map into url.Values, the shape a
// form-encoded token request body needs. Returns nil (not an empty,
// non-nil map) when there's nothing to add, so callers can tell "no extra
// params" apart from "an empty-but-present set".
func toURLValues(m map[string]string) url.Values {
	if len(m) == 0 {
		return nil
	}
	v := make(url.Values, len(m))
	for key, val := range m {
		v.Set(key, val)
	}
	return v
}

// Mode returns the processing mode. Injecting a header needs no body inspection, so
// this uses the lighter header-phase hook (unlike aws-authentication's SigV4 payload
// hashing). Response headers are processed only when purgeStatusCodes is non-empty
// (always false for the static-token path - see GetPolicy).
func (p *Policy) Mode() policy.ProcessingMode {
	responseHeaderMode := policy.HeaderModeSkip
	if len(p.purgeStatusCodes) > 0 {
		responseHeaderMode = policy.HeaderModeProcess
	}
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: responseHeaderMode,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// getStringParam safely extracts a string parameter, returning "" if absent
// or the wrong type. Leading/trailing whitespace is trimmed: credential
// values pasted from config files or secret stores frequently carry a stray
// trailing newline or space, which is invisible in logs but silently
// corrupts a client-secret comparison at the token endpoint.
func getStringParam(params map[string]interface{}, key string) string {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			return strings.TrimSpace(str)
		}
	}
	return ""
}

// getStringParamOrDefault extracts a string parameter, falling back to def when the
// key is absent or the wrong type - but NOT when it's an explicitly empty string, so
// a param like valuePrefix can be intentionally cleared to "no prefix".
func getStringParamOrDefault(params map[string]interface{}, key, def string) string {
	val, ok := params[key]
	if !ok {
		return def
	}
	str, ok := val.(string)
	if !ok {
		return def
	}
	return strings.TrimSpace(str)
}

// getRequiredStringParam extracts a required, non-empty string parameter,
// trimmed per getStringParam.
func getRequiredStringParam(params map[string]interface{}, key string) (string, error) {
	val, ok := params[key]
	if !ok {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	str, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("'%s' must be a string", key)
	}
	str = strings.TrimSpace(str)
	if str == "" {
		return "", fmt.Errorf("'%s' cannot be empty", key)
	}
	return str, nil
}

// getBoolParam extracts an optional boolean parameter, falling back to def
// if the key is absent or the wrong type - matching this policy's other
// optional fields' permissive, best-effort extraction style.
func getBoolParam(params map[string]interface{}, key string, def bool) bool {
	if val, ok := params[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return def
}

// getIntParam extracts an optional integer parameter, tolerating the
// several numeric shapes JSON/YAML decoding can produce (int, int64,
// float64) - falling back to def if the key is absent, the wrong type, or
// negative (retry counts and thresholds have no meaningful negative value).
func getIntParam(params map[string]interface{}, key string, def int) int {
	val, ok := params[key]
	if !ok {
		return def
	}
	var n int
	switch v := val.(type) {
	case int:
		n = v
	case int64:
		n = int(v)
	case float64:
		n = int(v)
	default:
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

// getDurationParam extracts an optional Go-duration-formatted string
// parameter (e.g. "10s", "1h"), falling back to def if the key is absent,
// the wrong type, or unparsable - matching this policy's other optional
// fields' permissive, best-effort extraction style.
func getDurationParam(params map[string]interface{}, key string, def time.Duration) time.Duration {
	if val, ok := params[key]; ok {
		if str, ok := val.(string); ok {
			if d, err := time.ParseDuration(strings.TrimSpace(str)); err == nil {
				return d
			}
		}
	}
	return def
}

// getStringMapParam extracts an optional flat string-to-string map
// parameter (tokenRequestParams, tokenRequestHeaders) by key. Absent or
// wrong-shaped input just yields no entries rather than an error, matching
// how the other optional fields in this policy behave.
func getStringMapParam(params map[string]interface{}, key string) map[string]string {
	raw, ok := params[key]
	if !ok {
		return nil
	}
	m, ok := raw.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := v.(string); ok {
			if trimmed := strings.TrimSpace(s); trimmed != "" {
				out[k] = trimmed
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// getPurgeStatusCodesParam extracts "tokenPurgeStatusCodes" - the
// upstream response status codes that purge the cached token (see
// OnResponseHeaders). Absent or wrong-shaped input falls back to def
// (defaultPurgeStatusCodes), matching this policy's other optional fields.
// An explicit empty list ([]), unlike an absent key, is honored as-is - it
// disables response-phase purging entirely rather than falling back to the
// default, since that's the only way to opt out.
func getPurgeStatusCodesParam(params map[string]interface{}, key string, def []int) map[int]struct{} {
	codes := def
	if raw, ok := params[key]; ok {
		if arr, ok := raw.([]interface{}); ok {
			parsed := make([]int, 0, len(arr))
			for _, v := range arr {
				switch n := v.(type) {
				case int:
					parsed = append(parsed, n)
				case int64:
					parsed = append(parsed, int(n))
				case float64:
					parsed = append(parsed, int(n))
				case string:
					if code, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
						parsed = append(parsed, code)
					}
				}
			}
			codes = parsed
		}
	}
	set := make(map[int]struct{}, len(codes))
	for _, c := range codes {
		set[c] = struct{}{}
	}
	return set
}

// validateAndExtractParams validates and extracts all policy params.
//
// bearerToken and tokenEndpoint/clientId/clientSecret are mutually exclusive auth
// paths - configuring both, or neither, is rejected here. When bearerToken is set,
// every token-endpoint-only field below is simply unused.
//
// grantType defaults to client_credentials. Fields specific to one grant
// (username/password) are validated conditionally on grantType, since JSON
// Schema's static `required` can't express "required only when grantType is X".
// clientAuthMethod defaults to client_secret_basic and applies to both grants.
func validateAndExtractParams(params map[string]interface{}) (oauth2Params, error) {
	var p oauth2Params

	p.bearerToken = getStringParam(params, "bearerToken")
	tokenEndpointRaw := getStringParam(params, "tokenEndpoint")
	clientIDRaw := getStringParam(params, "clientId")
	clientSecretRaw := getStringParam(params, "clientSecret")
	hasTokenEndpointFields := tokenEndpointRaw != "" || clientIDRaw != "" || clientSecretRaw != ""

	switch {
	case p.bearerToken != "" && hasTokenEndpointFields:
		return oauth2Params{}, fmt.Errorf(
			"'bearerToken' cannot be combined with 'tokenEndpoint'/'clientId'/'clientSecret' - configure exactly one authentication path")
	case p.bearerToken == "" && !hasTokenEndpointFields:
		return oauth2Params{}, fmt.Errorf(
			"either 'bearerToken' or 'tokenEndpoint'+'clientId'+'clientSecret' must be configured")
	}

	p.headerName = getStringParamOrDefault(params, "headerName", defaultHeaderName)
	if p.headerName == "" {
		// Defensive only: policy-definition.yaml's minLength: 1 should
		// already reject an explicit empty string before this runs.
		p.headerName = defaultHeaderName
	}
	p.valuePrefix = getStringParamOrDefault(params, "valuePrefix", defaultValuePrefix)

	if p.bearerToken != "" {
		// Static-token path: nothing else to validate or default.
		return p, nil
	}

	p.grantType = getStringParam(params, "grantType")
	if p.grantType == "" {
		p.grantType = GrantTypeClientCredentials
	}
	if p.grantType != GrantTypeClientCredentials && p.grantType != GrantTypePassword {
		return oauth2Params{}, fmt.Errorf("'grantType' must be one of %q, %q", GrantTypeClientCredentials, GrantTypePassword)
	}

	p.clientAuthMethod = getStringParam(params, "clientAuthMethod")
	if p.clientAuthMethod == "" {
		p.clientAuthMethod = ClientAuthMethodBasic
	}
	if p.clientAuthMethod != ClientAuthMethodBasic && p.clientAuthMethod != ClientAuthMethodPost {
		return oauth2Params{}, fmt.Errorf("'clientAuthMethod' must be one of %q, %q", ClientAuthMethodBasic, ClientAuthMethodPost)
	}

	var err error
	p.tokenEndpoint, err = getRequiredStringParam(params, "tokenEndpoint")
	if err != nil {
		return oauth2Params{}, err
	}
	p.clientID, err = getRequiredStringParam(params, "clientId")
	if err != nil {
		return oauth2Params{}, err
	}
	p.clientSecret, err = getRequiredStringParam(params, "clientSecret")
	if err != nil {
		return oauth2Params{}, err
	}
	p.tokenRequestParams = getStringMapParam(params, "tokenRequestParams")
	p.tokenRequestHeaders = getStringMapParam(params, "tokenRequestHeaders")
	p.requestTimeout = getDurationParam(params, "tokenRequestTimeout", defaultTokenRequestTimeout)
	p.tokenTTLFallback = getDurationParam(params, "defaultTokenTTL", defaultTokenTTLFallback)
	p.expiryBuffer = getDurationParam(params, "expiryBuffer", defaultExpiryBuffer)
	if p.expiryBuffer < 0 {
		// A negative buffer has no sane meaning here (see getIntParam's
		// identical treatment of negative retry counts) - fall back rather
		// than let it invert the freshness check.
		p.expiryBuffer = defaultExpiryBuffer
	}
	p.purgeStatusCodes = getPurgeStatusCodesParam(params, "tokenPurgeStatusCodes", defaultPurgeStatusCodes)

	p.proxyURL = getStringParam(params, "proxyURL")
	p.tlsCaCertPath = getStringParam(params, "tlsCaCertPath")
	p.tlsInsecureSkipVerify = getBoolParam(params, "tlsInsecureSkipVerify", false)
	if p.tlsInsecureSkipVerify {
		slog.Warn("OAuth2Generator: tlsInsecureSkipVerify is enabled - TLS certificate verification for the token endpoint is disabled; this must never be used against a real identity provider")
	}

	p.tokenRequestMaxRetries = getIntParam(params, "tokenRequestMaxRetries", defaultTokenRequestMaxRetries)

	if p.grantType == GrantTypePassword {
		p.username, err = getRequiredStringParam(params, "username")
		if err != nil {
			return oauth2Params{}, err
		}
		p.password, err = getRequiredStringParam(params, "password")
		if err != nil {
			return oauth2Params{}, err
		}
	}

	return p, nil
}

// OnRequestHeaders obtains (fetching/reusing a cached token, or reading the
// directly-supplied one) the credential and injects it into headerName
// (default Authorization, prefixed per valuePrefix, default "Bearer ")
// before the request is forwarded to the upstream backend.
func (p *Policy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) policy.RequestHeaderAction {
	slog.Debug("OAuth2Generator: authenticating outbound request", "method", reqCtx.Method, "path", reqCtx.Path,
		"mode", p.mode, "grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

	tok, err := p.retrieveToken()
	if err != nil {
		return p.authFailure(reqCtx.SharedContext, "failed to obtain upstream credential", err)
	}

	p.authSuccess(reqCtx.SharedContext)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			p.headerName: buildHeaderValue(p.valuePrefix, tok.AccessToken),
		},
	}
}

// OnResponseHeaders purges the cached token when the upstream responds with one of
// purgeStatusCodes (default: 401) - the token was rejected, e.g. revoked out-of-band.
// Doesn't retry the current request; purging only guarantees the next one fetches
// fresh. Only reached when purgeStatusCodes is non-empty (never for static-token).
func (p *Policy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, _ map[string]interface{}) policy.ResponseHeaderAction {
	if _, purge := p.purgeStatusCodes[respCtx.ResponseStatus]; purge {
		slog.Warn("OAuth2Generator: upstream rejected the cached token, purging it for the next request",
			"status", respCtx.ResponseStatus, "grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)
		p.tokenSource.Purge()
	}
	return policy.DownstreamResponseHeaderModifications{}
}

// retrieveToken fetches the current (possibly cached/refreshed) access token
// from the token source built once in GetPolicy.
func (p *Policy) retrieveToken() (*Token, error) {
	fetch := p.tokenFunc
	if fetch == nil {
		fetch = p.tokenSource.Token
	}
	return fetch()
}

// authType returns the AuthContext.AuthType value for this instance's mode -
// see AuthType/AuthTypeStaticToken.
func (p *Policy) authType() string {
	if p.mode == ModeStaticToken {
		return AuthTypeStaticToken
	}
	return AuthType
}

// credentialID returns the AuthContext.CredentialID value for this
// instance's mode: clientID for the token-endpoint path, or a fixed
// placeholder for the static-token path, which has no client identity of its
// own to report.
func (p *Policy) credentialID() string {
	if p.mode == ModeStaticToken {
		return "static-token"
	}
	return p.clientID
}

// authProperties returns the AuthContext.Properties for this instance's
// mode. grantType/tokenEndpoint only apply to (and are only populated for)
// the token-endpoint path.
func (p *Policy) authProperties() map[string]string {
	props := map[string]string{"mode": p.mode}
	if p.mode == ModeTokenEndpoint {
		props["grantType"] = p.grantType
		props["tokenEndpoint"] = p.tokenEndpoint
	}
	return props
}

// authFailure builds a 502 Bad Gateway ImmediateResponse for gateway-side
// credential-acquisition failures. 502 (not 401) is deliberate: the caller's
// request was fine — it is the gateway's own upstream credentials or the
// token endpoint that failed, a gateway-to-backend problem rather than a
// client-auth rejection.
func (p *Policy) authFailure(shared *policy.SharedContext, reason string, cause error) policy.RequestHeaderAction {
	slog.Error("OAuth2Generator: credential acquisition failed", "reason", reason, "error", cause,
		"mode", p.mode, "grantType", p.grantType, "tokenEndpoint", p.tokenEndpoint, "clientId", p.clientID)

	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      p.authType(),
		CredentialID:  p.credentialID(),
		Properties:    p.authProperties(),
		Previous:      shared.AuthContext,
	}

	body, _ := json.Marshal(map[string]string{
		"error":   "Bad Gateway",
		"message": "failed to authenticate request to upstream service",
	})
	return policy.ImmediateResponse{
		StatusCode: http.StatusBadGateway,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}

// authSuccess records a successful credential injection in the shared
// AuthContext, preserving any existing chain (e.g. an earlier inbound auth
// policy) via Previous.
func (p *Policy) authSuccess(shared *policy.SharedContext) {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      p.authType(),
		CredentialID:  p.credentialID(),
		Properties:    p.authProperties(),
		Previous:      shared.AuthContext,
	}
}
