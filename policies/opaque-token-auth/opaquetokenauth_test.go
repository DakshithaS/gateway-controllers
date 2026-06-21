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

package opaquetokenauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	"github.com/wso2/api-platform/sdk/core/utils/cache"
)

// ─── Test helpers ────────────────────────────────────────────────────────────

func newPolicy() *OpaqueTokenAuthPolicy {
	return &OpaqueTokenAuthPolicy{
		cache: cache.NewInMemoryCache[*cachedIntrospection](cacheName, cacheMaxSize, 0, cache.LRUEvictionPolicy),
	}
}

// activeResponder writes the given introspection claims as a JSON response.
func activeResponder(claims map[string]interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	}
}

func newServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(handler)
	t.Cleanup(s.Close)
	return s
}

// provider builds a single introspection provider config map.
func provider(name, uri string, introspectionExtra map[string]interface{}) map[string]interface{} {
	introspection := map[string]interface{}{"uri": uri}
	for k, v := range introspectionExtra {
		introspection[k] = v
	}
	return map[string]interface{}{"name": name, "introspection": introspection}
}

// baseParams wraps providers into a params map.
func baseParams(providers ...map[string]interface{}) map[string]interface{} {
	list := make([]interface{}, 0, len(providers))
	for _, p := range providers {
		list = append(list, p)
	}
	return map[string]interface{}{"introspectionProviders": list}
}

func bearerHeader(token string) map[string][]string {
	return map[string][]string{"authorization": {"Bearer " + token}}
}

func execute(t *testing.T, p *OpaqueTokenAuthPolicy, params map[string]interface{}, headers map[string][]string) (*policy.RequestHeaderContext, policy.RequestHeaderAction) {
	t.Helper()
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Headers:       policy.NewHeaders(headers),
	}
	action := p.OnRequestHeaders(context.Background(), reqCtx, params)
	return reqCtx, action
}

func assertSuccess(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction) policy.UpstreamRequestHeaderModifications {
	t.Helper()
	mods, ok := action.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", action)
	}
	if reqCtx.AuthContext == nil || !reqCtx.AuthContext.Authenticated {
		t.Fatalf("expected authenticated AuthContext, got %+v", reqCtx.AuthContext)
	}
	return mods
}

func assertFailure(t *testing.T, reqCtx *policy.RequestHeaderContext, action policy.RequestHeaderAction, statusCode int) policy.ImmediateResponse {
	t.Helper()
	ir, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", action)
	}
	if ir.StatusCode != statusCode {
		t.Fatalf("expected status %d, got %d", statusCode, ir.StatusCode)
	}
	if reqCtx.AuthContext == nil || reqCtx.AuthContext.Authenticated {
		t.Fatalf("expected unauthenticated AuthContext, got %+v", reqCtx.AuthContext)
	}
	return ir
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func TestActiveTokenSucceeds(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active":    true,
		"sub":       "user-123",
		"iss":       "https://idp.example",
		"client_id": "app-1",
		"scope":     "read write",
		"aud":       "my-api",
		"org":       "acme",
	}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-abc"))
	assertSuccess(t, reqCtx, action)

	ac := reqCtx.AuthContext
	if ac.AuthType != AuthType {
		t.Errorf("AuthType = %q, want %q", ac.AuthType, AuthType)
	}
	if ac.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", ac.Subject)
	}
	if ac.Issuer != "https://idp.example" {
		t.Errorf("Issuer = %q", ac.Issuer)
	}
	if ac.CredentialID != "app-1" {
		t.Errorf("CredentialID = %q, want app-1", ac.CredentialID)
	}
	if !ac.Scopes["read"] || !ac.Scopes["write"] {
		t.Errorf("Scopes = %v, want read+write", ac.Scopes)
	}
	if ac.Properties["org"] != "acme" {
		t.Errorf("Properties[org] = %q, want acme", ac.Properties["org"])
	}
}

func TestInactiveTokenFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": false}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-abc"))
	assertFailure(t, reqCtx, action, 401)
}

func TestClientSecretBasic(t *testing.T) {
	var gotUser, gotPass string
	var gotOK bool
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, map[string]interface{}{
		"clientId": "client-x", "clientSecret": "secret-y", "authStyle": "basic",
	}))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if !gotOK || gotUser != "client-x" || gotPass != "secret-y" {
		t.Errorf("basic auth = (%q,%q,%v), want (client-x,secret-y,true)", gotUser, gotPass, gotOK)
	}
}

func TestClientSecretPost(t *testing.T) {
	var gotClientID, gotSecret, gotAuthHeader string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotClientID = r.PostFormValue("client_id")
		gotSecret = r.PostFormValue("client_secret")
		gotAuthHeader = r.Header.Get("Authorization")
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, map[string]interface{}{
		"clientId": "client-x", "clientSecret": "secret-y", "authStyle": "post",
	}))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if gotClientID != "client-x" || gotSecret != "secret-y" {
		t.Errorf("post creds = (%q,%q), want (client-x,secret-y)", gotClientID, gotSecret)
	}
	if gotAuthHeader != "" {
		t.Errorf("Authorization header should be empty for client_secret_post, got %q", gotAuthHeader)
	}
}

func TestStaticBearerToken(t *testing.T) {
	var gotAuth string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, map[string]interface{}{
		"bearerToken": "introspect-token",
	}))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if gotAuth != "Bearer introspect-token" {
		t.Errorf("Authorization = %q, want 'Bearer introspect-token'", gotAuth)
	}
}

func TestTokenAndHintSent(t *testing.T) {
	var gotToken, gotHint string
	srv := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotToken = r.PostFormValue("token")
		gotHint = r.PostFormValue("token_type_hint")
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		activeResponder(map[string]interface{}{"active": true, "sub": "u"})(w, r)
	})
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("opaque-xyz"))
	assertSuccess(t, reqCtx, action)
	if gotToken != "opaque-xyz" {
		t.Errorf("token = %q, want opaque-xyz", gotToken)
	}
	if gotHint != "access_token" {
		t.Errorf("token_type_hint = %q, want access_token (default)", gotHint)
	}
}

func TestMissingHeaderFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	params := baseParams(provider("idp", srv.URL, nil))

	reqCtx, action := execute(t, newPolicy(), params, map[string][]string{})
	assertFailure(t, reqCtx, action, 401)
}

func TestWrongSchemeFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	params := baseParams(provider("idp", srv.URL, nil))

	headers := map[string][]string{"authorization": {"Basic dXNlcjpwYXNz"}}
	reqCtx, action := execute(t, newPolicy(), params, headers)
	assertFailure(t, reqCtx, action, 401)
}

func TestForwardTokenStripped(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["forwardToken"] = false

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	mods := assertSuccess(t, reqCtx, action)
	if !contains(mods.HeadersToRemove, "Authorization") {
		t.Errorf("expected Authorization to be removed, got %v", mods.HeadersToRemove)
	}
}

func TestForwardTokenMoved(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u"}))
	params := baseParams(provider("idp", srv.URL, nil))
	// defaults: forwardToken true, forwardedTokenHeader x-forwarded-authorization

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	mods := assertSuccess(t, reqCtx, action)
	if mods.HeadersToSet["X-Forwarded-Authorization"] != "Bearer tok" {
		t.Errorf("forwarded header = %q, want 'Bearer tok'", mods.HeadersToSet["X-Forwarded-Authorization"])
	}
	if !contains(mods.HeadersToRemove, "Authorization") {
		t.Errorf("expected original Authorization removed, got %v", mods.HeadersToRemove)
	}
}

func TestClaimMappings(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "username": "alice",
	}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["claimMappings"] = map[string]interface{}{"username": "X-User-Name"}

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	mods := assertSuccess(t, reqCtx, action)
	if mods.HeadersToSet["X-User-Name"] != "alice" {
		t.Errorf("X-User-Name = %q, want alice", mods.HeadersToSet["X-User-Name"])
	}
}

func TestScopeEnforcement(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "scope": "read",
	}))

	t.Run("pass", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredScopes"] = []interface{}{"read"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertSuccess(t, reqCtx, action)
	})
	t.Run("fail", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredScopes"] = []interface{}{"admin"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertFailure(t, reqCtx, action, 401)
	})
}

func TestAudienceEnforcement(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "aud": []interface{}{"api-a", "api-b"},
	}))

	t.Run("pass", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["audiences"] = []interface{}{"api-b"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertSuccess(t, reqCtx, action)
	})
	t.Run("fail", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["audiences"] = []interface{}{"api-c"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertFailure(t, reqCtx, action, 401)
	})
}

func TestRequiredClaims(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{
		"active": true, "sub": "u", "tenant": "acme",
	}))

	t.Run("pass", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredClaims"] = map[string]interface{}{"tenant": "acme"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertSuccess(t, reqCtx, action)
	})
	t.Run("fail", func(t *testing.T) {
		params := baseParams(provider("idp", srv.URL, nil))
		params["requiredClaims"] = map[string]interface{}{"tenant": "other"}
		reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
		assertFailure(t, reqCtx, action, 401)
	})
}

func TestProviderFallback(t *testing.T) {
	inactive := newServer(t, activeResponder(map[string]interface{}{"active": false}))
	active := newServer(t, activeResponder(map[string]interface{}{"active": true, "sub": "u2"}))
	params := baseParams(
		provider("idp-a", inactive.URL, nil),
		provider("idp-b", active.URL, nil),
	)

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if reqCtx.AuthContext.Subject != "u2" {
		t.Errorf("Subject = %q, want u2 (from second provider)", reqCtx.AuthContext.Subject)
	}
}

func TestIssuerSelection(t *testing.T) {
	var aCount, bCount int64
	srvA := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&aCount, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "ua"})(w, r)
	})
	srvB := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&bCount, 1)
		activeResponder(map[string]interface{}{"active": true, "sub": "ub"})(w, r)
	})
	params := baseParams(
		provider("idp-a", srvA.URL, nil),
		provider("idp-b", srvB.URL, nil),
	)
	params["issuers"] = []interface{}{"idp-b"}

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertSuccess(t, reqCtx, action)
	if reqCtx.AuthContext.Subject != "ub" {
		t.Errorf("Subject = %q, want ub", reqCtx.AuthContext.Subject)
	}
	if atomic.LoadInt64(&aCount) != 0 {
		t.Errorf("provider idp-a should not be called, got %d calls", aCount)
	}
	if atomic.LoadInt64(&bCount) != 1 {
		t.Errorf("provider idp-b calls = %d, want 1", bCount)
	}
}

func TestNoProvidersConfiguredFails(t *testing.T) {
	params := map[string]interface{}{}
	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestIssuerSelectionNoMatchFails(t *testing.T) {
	srv := newServer(t, activeResponder(map[string]interface{}{"active": true}))
	params := baseParams(provider("idp", srv.URL, nil))
	params["issuers"] = []interface{}{"nonexistent"}

	reqCtx, action := execute(t, newPolicy(), params, bearerHeader("tok"))
	assertFailure(t, reqCtx, action, 401)
}

func TestMode(t *testing.T) {
	m := newPolicy().Mode()
	if m.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("RequestHeaderMode = %v, want PROCESS", m.RequestHeaderMode)
	}
	if m.RequestBodyMode != policy.BodyModeSkip || m.ResponseHeaderMode != policy.HeaderModeSkip || m.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected all non-request-header modes to be SKIP, got %+v", m)
	}
}

func TestGetPolicy(t *testing.T) {
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil || p == nil {
		t.Fatalf("GetPolicy returned (%v, %v)", p, err)
	}
}
