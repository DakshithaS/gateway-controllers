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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultHeader      = "x-jwt-assertion"
	defaultTokenExpiry = 15 * time.Minute
	defaultAlgorithm   = "RS256"
)

// BackendJWTPolicy generates a signed JWT from the authenticated user context
// and injects it into the upstream request header. It is designed to run after
// an authentication policy (e.g. jwt-auth, basic-auth, api-key-auth).
type BackendJWTPolicy struct {
	keyMu    sync.RWMutex
	keyCache map[[32]byte]crypto.PrivateKey
}

var ins = &BackendJWTPolicy{
	keyCache: make(map[[32]byte]crypto.PrivateKey),
}

// GetPolicy is the v1alpha2 factory entry point.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	return ins, nil
}

func (p *BackendJWTPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// Validate checks that the signing key is present and parseable at config load time.
func (p *BackendJWTPolicy) Validate(params map[string]interface{}) error {
	pemBytes, err := extractSigningKeyPEM(params)
	if err != nil {
		return fmt.Errorf("invalid signingKey: %w", err)
	}
	if _, err := parsePrivateKey(pemBytes); err != nil {
		return fmt.Errorf("invalid signingKey: %w", err)
	}
	return nil
}

// OnRequestHeaders generates a signed JWT from the auth context and sets it on the upstream request.
func (p *BackendJWTPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	requireAuth := getBool(params, "requireAuthentication", false)
	authCtx := reqCtx.SharedContext.AuthContext

	if authCtx == nil || !authCtx.Authenticated {
		if requireAuth {
			slog.Debug("Backend JWT: no authenticated context, rejecting request")
			return policy.ImmediateResponse{
				StatusCode: 401,
				Headers:    map[string]string{"content-type": "application/json"},
				Body:       []byte(`{"error":"Unauthorized","message":"Authentication is required to generate a backend JWT"}`),
			}
		}
		slog.Debug("Backend JWT: no authenticated context, passing through")
		return policy.UpstreamRequestHeaderModifications{}
	}

	pemBytes, err := extractSigningKeyPEM(params)
	if err != nil {
		slog.Error("Backend JWT: failed to extract signing key", "error", err)
		return internalError()
	}

	privateKey, err := p.loadKey(pemBytes)
	if err != nil {
		slog.Error("Backend JWT: failed to parse signing key", "error", err)
		return internalError()
	}

	algorithm := getString(params, "algorithm", defaultAlgorithm)
	signingMethod, err := getSigningMethod(algorithm, privateKey)
	if err != nil {
		slog.Error("Backend JWT: unsupported algorithm or mismatched key type", "algorithm", algorithm, "error", err)
		return internalError()
	}

	issuer := getString(params, "issuer", "")
	expiry := parseDuration(getString(params, "tokenExpiry", ""), defaultTokenExpiry)

	now := time.Now()
	claims := jwt.MapClaims{
		"iat":       now.Unix(),
		"exp":       now.Add(expiry).Unix(),
		"sub":       authCtx.Subject,
		"auth_type": authCtx.AuthType,
	}
	if issuer != "" {
		claims["iss"] = issuer
	}
	if authCtx.Issuer != "" {
		claims["original_iss"] = authCtx.Issuer
	}
	if len(authCtx.Audience) > 0 {
		claims["aud"] = authCtx.Audience
	}
	if authCtx.CredentialID != "" {
		claims["credential_id"] = authCtx.CredentialID
	}

	// Map selected AuthContext.Properties keys to JWT claims.
	if mappingsRaw, ok := params["claimMappings"]; ok {
		if mappings, ok := mappingsRaw.(map[string]interface{}); ok {
			for propKey, claimNameRaw := range mappings {
				claimName, ok := claimNameRaw.(string)
				if !ok {
					continue
				}
				if val, ok := authCtx.Properties[propKey]; ok {
					claims[claimName] = val
				}
			}
		}
	}

	// Apply custom claims — string values starting with "$ctx:" resolve from request context.
	if customRaw, ok := params["customClaims"]; ok {
		if custom, ok := customRaw.(map[string]interface{}); ok {
			for k, v := range custom {
				strVal, ok := v.(string)
				if !ok {
					// Non-string values (numbers, booleans) pass through as-is.
					claims[k] = v
					continue
				}
				resolved, ok := resolveClaimValue(strVal, reqCtx)
				if !ok {
					slog.Debug("Backend JWT: skipping claim — context variable not resolvable",
						"claim", k, "ref", strVal)
					continue
				}
				claims[k] = resolved
			}
		}
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		slog.Error("Backend JWT: failed to sign token", "error", err)
		return internalError()
	}

	headerName := getString(params, "header", defaultHeader)
	slog.Debug("Backend JWT: generated token", "header", headerName, "subject", authCtx.Subject)

	return policy.UpstreamRequestHeaderModifications{
		HeadersToSet: map[string]string{
			headerName: signed,
		},
	}
}

// loadKey returns a cached private key, parsing and caching it on first use.
func (p *BackendJWTPolicy) loadKey(pemBytes []byte) (crypto.PrivateKey, error) {
	fingerprint := sha256.Sum256(pemBytes)

	p.keyMu.RLock()
	key, ok := p.keyCache[fingerprint]
	p.keyMu.RUnlock()
	if ok {
		return key, nil
	}

	parsed, err := parsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	p.keyMu.Lock()
	p.keyCache[fingerprint] = parsed
	p.keyMu.Unlock()

	return parsed, nil
}

// extractSigningKeyPEM reads PEM bytes from params["signingKey"].inline or params["signingKey"].path.
func extractSigningKeyPEM(params map[string]interface{}) ([]byte, error) {
	signingKeyRaw, ok := params["signingKey"]
	if !ok {
		return nil, fmt.Errorf("signingKey is required")
	}
	signingKeyMap, ok := signingKeyRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("signingKey must be an object with 'inline' or 'path'")
	}

	if inlineRaw, ok := signingKeyMap["inline"]; ok {
		inline, ok := inlineRaw.(string)
		if !ok || inline == "" {
			return nil, fmt.Errorf("signingKey.inline must be a non-empty string")
		}
		return []byte(inline), nil
	}

	if pathRaw, ok := signingKeyMap["path"]; ok {
		path, ok := pathRaw.(string)
		if !ok || path == "" {
			return nil, fmt.Errorf("signingKey.path must be a non-empty string")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading key file %q: %w", path, err)
		}
		return data, nil
	}

	return nil, fmt.Errorf("signingKey must specify either 'inline' or 'path'")
}

// parsePrivateKey decodes and parses a PEM-encoded RSA or ECDSA private key.
func parsePrivateKey(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no valid PEM block found in signing key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported PKCS8 key type: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q; expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY", block.Type)
	}
}

// getSigningMethod returns the jwt.SigningMethod for the given algorithm string,
// validating that the private key type matches.
func getSigningMethod(algorithm string, key crypto.PrivateKey) (jwt.SigningMethod, error) {
	switch algorithm {
	case "RS256":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("RS256 requires an RSA private key, got %T", key)
		}
		return jwt.SigningMethodRS256, nil
	case "RS384":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("RS384 requires an RSA private key, got %T", key)
		}
		return jwt.SigningMethodRS384, nil
	case "RS512":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("RS512 requires an RSA private key, got %T", key)
		}
		return jwt.SigningMethodRS512, nil
	case "ES256":
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("ES256 requires an ECDSA private key, got %T", key)
		}
		return jwt.SigningMethodES256, nil
	case "ES384":
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("ES384 requires an ECDSA private key, got %T", key)
		}
		return jwt.SigningMethodES384, nil
	case "ES512":
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return nil, fmt.Errorf("ES512 requires an ECDSA private key, got %T", key)
		}
		return jwt.SigningMethodES512, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q; supported: RS256, RS384, RS512, ES256, ES384, ES512", algorithm)
	}
}

func getString(params map[string]interface{}, key, defaultVal string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return defaultVal
}

func getBool(params map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

const ctxPrefix = "$ctx:"

// resolveClaimValue returns the value to use for a custom JWT claim.
// Values prefixed with "$ctx:" are resolved from the request context at runtime.
// Returns ("", false) when a context variable cannot be resolved — the caller
// silently skips the claim rather than treating it as an error.
func resolveClaimValue(value string, reqCtx *policy.RequestHeaderContext) (string, bool) {
	if !strings.HasPrefix(value, ctxPrefix) {
		return value, true
	}
	variable := strings.ToLower(strings.TrimPrefix(value, ctxPrefix))

	switch {
	case variable == "request.path":
		return reqCtx.Path, true
	case variable == "request.method":
		return reqCtx.Method, true
	case variable == "request.authority":
		return reqCtx.Authority, true
	case variable == "request.scheme":
		return reqCtx.Scheme, true
	case strings.HasPrefix(variable, "request.header."):
		name := strings.TrimPrefix(variable, "request.header.")
		vals := reqCtx.Headers.Get(name)
		if len(vals) == 0 {
			return "", false
		}
		return vals[0], true
	case variable == "api.id":
		return reqCtx.APIId, true
	case variable == "api.name":
		return reqCtx.APIName, true
	case variable == "api.version":
		return reqCtx.APIVersion, true
	case variable == "api.context":
		return reqCtx.APIContext, true
	case variable == "auth.subject":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.Subject, true
	case variable == "auth.type":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.AuthType, true
	case variable == "auth.credential_id":
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		return reqCtx.SharedContext.AuthContext.CredentialID, true
	case strings.HasPrefix(variable, "auth.property."):
		if reqCtx.SharedContext.AuthContext == nil {
			return "", false
		}
		key := strings.TrimPrefix(variable, "auth.property.")
		val, ok := reqCtx.SharedContext.AuthContext.Properties[key]
		return val, ok
	default:
		return "", false
	}
}

func internalError() policy.ImmediateResponse {
	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers:    map[string]string{"content-type": "application/json"},
		Body:       []byte(`{"error":"Internal Server Error"}`),
	}
}
