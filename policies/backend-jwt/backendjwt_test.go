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

package backendjwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func generateRSAKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return key, string(pemBytes)
}

func generateECKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ECDSA key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	return key, string(pemBytes)
}

func newRequestContext(authCtx *policy.AuthContext) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "test-request-id",
			Metadata:    make(map[string]interface{}),
			AuthContext: authCtx,
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/api/test",
		Method:  "GET",
	}
}

func baseParams(pemKey string) map[string]interface{} {
	return map[string]interface{}{
		"signingKey": map[string]interface{}{
			"inline": pemKey,
		},
		"algorithm":   "RS256",
		"issuer":      "https://gateway.example.com",
		"tokenExpiry": "15m",
	}
}

func decodeJWT(t *testing.T, tokenStr string, verifyKey interface{}) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})
	if err != nil {
		t.Fatalf("parse/verify JWT: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims are not MapClaims")
	}
	return claims
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestGetPolicySingleton(t *testing.T) {
	p1, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	p2, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned error: %v", err)
	}
	if p1 != p2 {
		t.Error("GetPolicy must return the same singleton instance")
	}
}

func TestMode(t *testing.T) {
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	mode := p.Mode()
	if mode.RequestHeaderMode != policy.HeaderModeProcess {
		t.Errorf("expected RequestHeaderMode=HeaderModeProcess, got %v", mode.RequestHeaderMode)
	}
	if mode.RequestBodyMode != policy.BodyModeSkip {
		t.Errorf("expected RequestBodyMode=BodyModeSkip, got %v", mode.RequestBodyMode)
	}
	if mode.ResponseHeaderMode != policy.HeaderModeSkip {
		t.Errorf("expected ResponseHeaderMode=HeaderModeSkip, got %v", mode.ResponseHeaderMode)
	}
	if mode.ResponseBodyMode != policy.BodyModeSkip {
		t.Errorf("expected ResponseBodyMode=BodyModeSkip, got %v", mode.ResponseBodyMode)
	}
}

func TestNoAuthContext_RequireAuth(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["requireAuthentication"] = true

	reqCtx := newRequestContext(nil)
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestNoAuthContext_NoRequireAuth(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(nil)
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}
	if len(mods.HeadersToSet) != 0 {
		t.Errorf("expected no headers set for unauthenticated pass-through, got %v", mods.HeadersToSet)
	}
}

func TestUnauthenticatedAuthContext_RequireAuth(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["requireAuthentication"] = true

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: false, AuthType: "jwt"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse, got %T", result)
	}
	if resp.StatusCode != 401 {
		t.Errorf("expected status 401, got %d", resp.StatusCode)
	}
}

func TestGeneratesJWTWithSubject(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "alice",
		Issuer:        "https://idp.example.com",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}

	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok {
		t.Fatalf("expected header %q to be set", defaultHeader)
	}

	claims := decodeJWT(t, tokenStr, &rsaKey.PublicKey)
	if claims["sub"] != "alice" {
		t.Errorf("expected sub=alice, got %v", claims["sub"])
	}
	if claims["auth_type"] != "jwt" {
		t.Errorf("expected auth_type=jwt, got %v", claims["auth_type"])
	}
	if claims["iss"] != "https://gateway.example.com" {
		t.Errorf("expected iss=https://gateway.example.com, got %v", claims["iss"])
	}
	if claims["original_iss"] != "https://idp.example.com" {
		t.Errorf("expected original_iss=https://idp.example.com, got %v", claims["original_iss"])
	}
}

func TestCustomClaims(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{
		"env":     "production",
		"version": "v2",
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "basic",
		Subject:       "bob",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["env"] != "production" {
		t.Errorf("expected env=production, got %v", claims["env"])
	}
	if claims["version"] != "v2" {
		t.Errorf("expected version=v2, got %v", claims["version"])
	}
}

func TestClaimMappings(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["claimMappings"] = map[string]interface{}{
		"app_id":  "application_id",
		"dept":    "department",
		"missing": "should_not_appear",
	}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "apikey",
		Subject:       "carol",
		Properties: map[string]string{
			"app_id": "app-xyz-123",
			"dept":   "engineering",
		},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["application_id"] != "app-xyz-123" {
		t.Errorf("expected application_id=app-xyz-123, got %v", claims["application_id"])
	}
	if claims["department"] != "engineering" {
		t.Errorf("expected department=engineering, got %v", claims["department"])
	}
	if _, present := claims["should_not_appear"]; present {
		t.Error("claim for missing property key must not appear in token")
	}
}

func TestTokenExpiry(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["tokenExpiry"] = "5m"

	// Truncate to whole seconds: iat/exp are Unix timestamps (second precision).
	before := time.Now().Truncate(time.Second)
	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "dave"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	after := time.Now().Truncate(time.Second).Add(time.Second)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	expRaw, ok := claims["exp"].(float64)
	if !ok {
		t.Fatal("exp claim missing or not a number")
	}
	iatRaw, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("iat claim missing or not a number")
	}

	expTime := time.Unix(int64(expRaw), 0)
	iatTime := time.Unix(int64(iatRaw), 0)
	diff := expTime.Sub(iatTime)

	if diff < 4*time.Minute || diff > 6*time.Minute {
		t.Errorf("expected exp-iat≈5m, got %v", diff)
	}
	if iatTime.Before(before) || iatTime.After(after) {
		t.Errorf("iat %v is outside [%v, %v]", iatTime, before, after)
	}
}

func TestRS256Signing(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "rs256-user"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)

	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok {
		t.Fatal("no JWT header set")
	}

	// Verify the token header uses RS256
	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if token.Method != jwt.SigningMethodRS256 {
		t.Errorf("expected RS256 signing method, got %v", token.Method.Alg())
	}

	// Verify signature using the public key
	decodeJWT(t, tokenStr, &rsaKey.PublicKey)
}

func TestES256Signing(t *testing.T) {
	ecKey, keyPEM := generateECKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": keyPEM},
		"algorithm":  "ES256",
		"issuer":     "https://gateway.example.com",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "ec-user"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)

	tokenStr, ok := mods.HeadersToSet[defaultHeader]
	if !ok {
		t.Fatal("no JWT header set")
	}

	token, _, err := jwt.NewParser().ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse unverified: %v", err)
	}
	if token.Method != jwt.SigningMethodES256 {
		t.Errorf("expected ES256 signing method, got %v", token.Method.Alg())
	}

	decodeJWT(t, tokenStr, &ecKey.PublicKey)
}

func TestCustomHeader(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["header"] = "x-custom-backend-token"

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "frank"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)

	if _, ok := mods.HeadersToSet[defaultHeader]; ok {
		t.Errorf("default header %q must not be set when custom header is configured", defaultHeader)
	}
	if _, ok := mods.HeadersToSet["x-custom-backend-token"]; !ok {
		t.Error("custom header x-custom-backend-token must be set")
	}
}

func TestInvalidPrivateKey(t *testing.T) {
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{
			"inline": "not-a-valid-pem-key",
		},
		"algorithm": "RS256",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "grace"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on invalid key, got %T", result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestMismatchedAlgorithmAndKey(t *testing.T) {
	_, rsaKeyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": rsaKeyPEM},
		"algorithm":  "ES256", // wrong: RSA key with ECDSA algorithm
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "henry"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)

	resp, ok := result.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("expected ImmediateResponse on key/algorithm mismatch, got %T", result)
	}
	if resp.StatusCode != 500 {
		t.Errorf("expected status 500, got %d", resp.StatusCode)
	}
}

func TestValidate_MissingKey(t *testing.T) {
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	err := p.Validate(map[string]interface{}{})
	if err == nil {
		t.Error("Validate must return error when signingKey is absent")
	}
}

func TestValidate_InvalidKeyMaterial(t *testing.T) {
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	err := p.Validate(map[string]interface{}{
		"signingKey": map[string]interface{}{
			"inline": "-----BEGIN RSA PRIVATE KEY-----\nbaddata\n-----END RSA PRIVATE KEY-----",
		},
	})
	if err == nil {
		t.Error("Validate must return error for invalid key material")
	}
}

func TestValidate_ValidKey(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	err := p.Validate(map[string]interface{}{
		"signingKey": map[string]interface{}{"inline": keyPEM},
	})
	if err != nil {
		t.Errorf("Validate must not return error for valid key: %v", err)
	}
}

func TestKeyFilePath(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	f, err := os.CreateTemp("", "backend-jwt-test-key-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(keyPEM); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	f.Close()

	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := map[string]interface{}{
		"signingKey": map[string]interface{}{"path": f.Name()},
		"algorithm":  "RS256",
	}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "irene"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods, ok := result.(policy.UpstreamRequestHeaderModifications)
	if !ok {
		t.Fatalf("expected UpstreamRequestHeaderModifications, got %T", result)
	}

	decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)
}

func TestKeyCaching(t *testing.T) {
	_, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)

	authCtx := &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "judy"}

	// Call twice; second call should hit the cache (no observable difference, but must not error).
	for i := 0; i < 2; i++ {
		reqCtx := newRequestContext(authCtx)
		result := p.OnRequestHeaders(context.Background(), reqCtx, params)
		if _, ok := result.(policy.UpstreamRequestHeaderModifications); !ok {
			t.Fatalf("call %d: expected UpstreamRequestHeaderModifications, got %T", i+1, result)
		}
	}

	// Verify only one key is cached.
	p.keyMu.RLock()
	count := len(p.keyCache)
	p.keyMu.RUnlock()
	if count != 1 {
		t.Errorf("expected 1 cached key, got %d", count)
	}
}

func TestAudienceAndCredentialID(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "apikey",
		Subject:       "ken",
		Audience:      []string{"service-a", "service-b"},
		CredentialID:  "client-abc",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["credential_id"] != "client-abc" {
		t.Errorf("expected credential_id=client-abc, got %v", claims["credential_id"])
	}
	audRaw, ok := claims["aud"]
	if !ok {
		t.Fatal("aud claim missing")
	}
	_ = audRaw // audience is present; exact type depends on JWT library serialisation
}

// ─── Context Claims Tests ─────────────────────────────────────────────────────

func TestContextClaims_StaticPassthrough(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"env": "production"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "leo"})
	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["env"] != "production" {
		t.Errorf("expected env=production, got %v", claims["env"])
	}
}

func TestContextClaims_RequestPath(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"req_path": "$ctx:request.path"}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "r1",
			Metadata:    make(map[string]interface{}),
			AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "mia"},
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/petstore/v1/pets/42",
		Method:  "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["req_path"] != "/petstore/v1/pets/42" {
		t.Errorf("expected req_path=/petstore/v1/pets/42, got %v", claims["req_path"])
	}
}

func TestContextClaims_RequestHeader(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"tenant": "$ctx:request.header.x-tenant-id"}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "r2",
			Metadata:    make(map[string]interface{}),
			AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "noah"},
		},
		Headers: policy.NewHeaders(map[string][]string{"x-tenant-id": {"acme-corp"}}),
		Path:    "/api/v1/data",
		Method:  "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["tenant"] != "acme-corp" {
		t.Errorf("expected tenant=acme-corp, got %v", claims["tenant"])
	}
}

func TestContextClaims_APIName(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"api": "$ctx:api.name"}

	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID:   "r3",
			Metadata:    make(map[string]interface{}),
			APIName:     "PetStoreAPI",
			AuthContext: &policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "olivia"},
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/api/v1",
		Method:  "GET",
	}

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["api"] != "PetStoreAPI" {
		t.Errorf("expected api=PetStoreAPI, got %v", claims["api"])
	}
}

func TestContextClaims_AuthCredentialID(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"applicationId": "$ctx:auth.credential_id"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "apikey",
		Subject:       "peter",
		CredentialID:  "app-xyz-999",
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["applicationId"] != "app-xyz-999" {
		t.Errorf("expected applicationId=app-xyz-999, got %v", claims["applicationId"])
	}
}

func TestContextClaims_AuthProperty(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"appName": "$ctx:auth.property.application_name"}

	reqCtx := newRequestContext(&policy.AuthContext{
		Authenticated: true,
		AuthType:      "jwt",
		Subject:       "quinn",
		Properties:    map[string]string{"application_name": "MyMobileApp"},
	})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if claims["appName"] != "MyMobileApp" {
		t.Errorf("expected appName=MyMobileApp, got %v", claims["appName"])
	}
}

func TestContextClaims_MissingHeader(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"tenant": "$ctx:request.header.x-tenant-id"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "ryan"})
	// x-tenant-id header is not set

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["tenant"]; present {
		t.Error("claim for missing header must be silently skipped")
	}
}

func TestContextClaims_UnknownVariable(t *testing.T) {
	rsaKey, keyPEM := generateRSAKey(t)
	p := &BackendJWTPolicy{keyCache: make(map[[32]byte]crypto.PrivateKey)}
	params := baseParams(keyPEM)
	params["customClaims"] = map[string]interface{}{"x": "$ctx:unknown.variable.name"}

	reqCtx := newRequestContext(&policy.AuthContext{Authenticated: true, AuthType: "jwt", Subject: "sam"})

	result := p.OnRequestHeaders(context.Background(), reqCtx, params)
	mods := result.(policy.UpstreamRequestHeaderModifications)
	claims := decodeJWT(t, mods.HeadersToSet[defaultHeader], &rsaKey.PublicKey)

	if _, present := claims["x"]; present {
		t.Error("claim for unknown $ctx variable must be silently skipped")
	}
}

func TestContextClaims_NilAuthContext(t *testing.T) {
	// resolveClaimValue must return ("", false) for auth.* when AuthContext is nil —
	// verify this directly since the full pipeline requires an authenticated context.
	reqCtx := &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{
			RequestID: "r9",
			Metadata:  make(map[string]interface{}),
			// AuthContext is deliberately nil
		},
		Headers: policy.NewHeaders(map[string][]string{}),
		Path:    "/test",
		Method:  "GET",
	}

	authVars := []string{
		"$ctx:auth.credential_id",
		"$ctx:auth.subject",
		"$ctx:auth.type",
		"$ctx:auth.property.foo",
	}
	for _, v := range authVars {
		resolved, ok := resolveClaimValue(v, reqCtx)
		if ok || resolved != "" {
			t.Errorf("resolveClaimValue(%q) with nil AuthContext: expected (\"\", false), got (%q, %v)", v, resolved, ok)
		}
	}
}
