# Backend JWT

Generates a signed JWT containing authenticated user information and injects it into the upstream request header. Run this policy **after** an authentication policy (e.g. `jwt-auth`, `basic-auth`, `api-key-auth`) to forward a gateway-signed assertion to backend services.

Backend services can verify the generated JWT using the gateway's corresponding public key — they do not need access to the original client credential (API key, OAuth token, etc.).

## How It Works

1. After an auth policy authenticates the request, the gateway's `AuthContext` is populated with the subject, auth type, issuer, audience, and any custom properties.
2. The Backend JWT policy reads this context, builds a JWT with the configured claims, and signs it with the configured RSA or ECDSA private key.
3. The signed JWT is set as the value of the configured upstream header (default: `x-jwt-assertion`).
4. The upstream service verifies the JWT using the matching public key.

Generated tokens are cached in memory for half their configured `tokenExpiry` (minimum 30 seconds). The cache key is derived from the authenticated client identity, API operation path, and all resolved claim values. Requests from the same client hitting the same operation within the cache window receive the previously signed token, avoiding repeated cryptographic operations. Dynamic custom claims that differ between requests (e.g. `$ctx:request.header.*`) produce separate cache entries, preserving correctness.

If no authentication context is present:
- With `requireAuthentication: false` (default) — the request is forwarded without a backend JWT.
- With `requireAuthentication: true` — the request is rejected with `401 Unauthorized`.

## Claims in the Generated Token

| Claim | Source |
|---|---|
| `sub` | `AuthContext.Subject` (JWT sub, basic-auth username, API key owner) |
| `iss` | `system.issuer` parameter |
| `iat` | Current time |
| `exp` | Current time + `system.tokenExpiry` |
| `auth_type` | `AuthContext.AuthType` (e.g. `jwt`, `basic`, `apikey`) |
| `original_iss` | `AuthContext.Issuer` — the original token issuer (JWT auth only) |
| `aud` | `AuthContext.Audience` (JWT auth only) |
| `credential_id` | `AuthContext.CredentialID` (OAuth client_id, API key credential) |
| _custom_ | Static values from `customClaims` |

## Configuration

### System Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `signingKey.inline` | string | — | PEM-encoded RSA or ECDSA private key (mutually exclusive with `path`) |
| `signingKey.path` | string | — | Path to a PEM private key file (mutually exclusive with `inline`) |
| `algorithm` | string | `SHA256withRSA` | Signing algorithm: `SHA256withRSA` (RSA) or `ES256` (ECDSA) or `NONE` (unsigned) |
| `issuer` | string | `""` | Value of the `iss` claim in generated tokens |
| `tokenExpiry` | string | `15m` | Token validity as a Go duration string (e.g. `"15m"`, `"1h"`) |

### User Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `header` | string | `x-jwt-assertion` | Upstream request header to set the generated JWT on |
| `requireAuthentication` | boolean | `false` | Reject unauthenticated requests with 401 when true |
| `claimMappings` | object | `{}` | Maps upstream JWT claim names to backend JWT claim names (see below) |
| `customClaims` | object | `{}` | Static or dynamic claim name→value pairs added to every generated token (see below) |

## Claim Mappings

`claimMappings` provides a structured way to forward upstream JWT claims into the backend JWT under a different name. The key is the backend JWT claim name to set; the value is the property key from the authenticated context (populated by `jwt-auth` from the upstream JWT's custom claims).

| `claimMappings` key | Source | Notes |
|---|---|---|
| any non-reserved name | `AuthContext.Properties[value]` | String values only |

Claims mapped to reserved names (`iss`, `sub`, `aud`, `exp`, `iat`) are skipped with a warning. Missing source properties are silently skipped. `customClaims` entries take precedence over `claimMappings` — if the same destination claim appears in both, `customClaims` wins.

```yaml
claimMappings:
  email: email           # forward AuthContext.Properties["email"] as "email"
  clientRole: role       # forward AuthContext.Properties["role"] as "clientRole"
  orgId: organization    # forward AuthContext.Properties["organization"] as "orgId"
```

## Dynamic Context Claims

`customClaims` values that start with `$ctx:` are resolved from the request context at runtime instead of being treated as static strings.

| Variable | Resolves to |
|---|---|
| `$ctx:request.path` | Request path (e.g. `/petstore/v1/pets/42`) |
| `$ctx:request.method` | HTTP method (`GET`, `POST`, …) |
| `$ctx:request.authority` | Host authority |
| `$ctx:request.scheme` | `http` or `https` |
| `$ctx:request.header.<name>` | First value of request header `<name>` (case-insensitive) |
| `$ctx:api.id` | API UUID |
| `$ctx:api.name` | API name |
| `$ctx:api.version` | API version |
| `$ctx:api.context` | API base context path |
| `$ctx:auth.subject` | Authenticated subject (same value as the `sub` claim) |
| `$ctx:auth.type` | Auth type (`jwt`, `basic`, `apikey`) |
| `$ctx:auth.credential_id` | Credential ID (OAuth client_id or API key) |
| `$ctx:auth.property.<key>` | Custom property from `AuthContext.Properties` |

Context variables that cannot be resolved (missing header, nil auth context, unknown variable name) are **silently skipped** — the claim is omitted from the token rather than causing an error or rejecting the request.

Use this to put an auth context value under a different claim name. For example, to expose the credential ID as `clientId` rather than `credential_id`:

```yaml
customClaims:
  clientId: $ctx:auth.credential_id
```

## Example

```yaml
# System-level (gateway config)
system:
  signingKey:
    path: /etc/certs/backend-jwt.key
  algorithm: SHA256withRSA
  issuer: https://gateway.example.com
  tokenExpiry: 15m

# Per-route policy attachment
policies:
  - name: backend-jwt
    parameters:
      header: x-jwt-assertion
      requireAuthentication: true
      claimMappings:
        email: email                                 # AuthContext.Properties["email"] → "email"
        clientRole: role                             # AuthContext.Properties["role"] → "clientRole"
      customClaims:
        env: production                              # static
        clientId: $ctx:auth.credential_id            # dynamic — credential ID
        clientName: $ctx:auth.property.client_name  # dynamic — from auth context property
        tenantId: $ctx:request.header.x-tenant-id   # dynamic — from request header
```

The upstream service then validates the `x-jwt-assertion` header using the public key matching the gateway's private key.

## Related Policies

- [`jwt-auth`](../../jwt-auth/v1.0/docs/jwt-authentication.md) — validates incoming JWTs from clients
- [`basic-auth`](../../basic-auth/) — authenticates clients with username/password; pairs well with Backend JWT to forward user identity
- [`api-key-auth`](../../api-key-auth/) — authenticates clients with API keys; pairs well with Backend JWT to forward client identity
