# Interceptor Service Policy

## Overview

The `interceptor-service` policy lets API authors plug a user-written HTTP
service into the gateway's request and response phases. The gateway becomes
the client of the user's service: it POSTs structured request/response data to
two well-known endpoints, and translates the JSON reply back into gateway
actions.

The interceptor service can be written in any language. The gateway speaks the
contract defined in `interceptor-service-open-api-v1.yaml`.

Use this policy when built-in policies cannot express your mediation logic —
for example, calling out to a custom PII redaction service, applying business
rules implemented in another team's service, or routing to dynamic upstreams
based on body inspection.

## Features

- Request-phase interception (mutate or short-circuit before the request hits
  upstream).
- Response-phase interception (mutate the response before it reaches the
  client).
- Header, body, and path mutation.
- Dynamic endpoint routing via the gateway's named-upstream mechanism.
- Direct respond — interceptor short-circuits the chain with its own status,
  headers, and body.
- Cross-phase `interceptorContext` round-trip via shared metadata.
- Per-phase passthrough-on-error for graceful degradation when the interceptor
  is unavailable.
- Configurable timeout and TLS posture.

## Configuration

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `endpoint` | string | yes | — | Base URL of the interceptor service. Policy posts to `{endpoint}/handle-request` and `{endpoint}/handle-response`. |
| `request` | object | one of `request` / `response` | — | Enable request-phase interception. |
| `request.includeRequestHeaders` | bool | no | `true` | Send request headers to the interceptor. |
| `request.includeRequestBody` | bool | no | `true` | Send request body (base64) to the interceptor. |
| `request.passthroughOnError` | bool | no | `false` | Continue upstream on interceptor failure. |
| `response` | object | one of `request` / `response` | — | Enable response-phase interception. |
| `response.includeRequestHeaders` | bool | no | `false` | Echo the original request headers. |
| `response.includeRequestBody` | bool | no | `false` | Echo the original request body. |
| `response.includeResponseHeaders` | bool | no | `true` | Send upstream response headers. |
| `response.includeResponseBody` | bool | no | `true` | Send upstream response body (base64). |
| `response.passthroughOnError` | bool | no | `false` | Forward the upstream response unchanged on interceptor failure. |
| `timeoutMillis` | int | no | `5000` | Per-call HTTP timeout (100–60000). |
| `tlsSkipVerify` | bool | no | `false` | Skip TLS verification when calling the interceptor. Dev/test only. |

## Wire Contract

The contract is defined in `interceptor-service-open-api-v1.yaml`. The policy
calls two endpoints:

- `POST {endpoint}/handle-request` — invoked at the request phase.
- `POST {endpoint}/handle-response` — invoked at the response phase.

Bodies are JSON. `requestBody`, `responseBody`, and the reply `body` field are
base64-encoded byte arrays.

### Request-phase request body (`handle-request`)

```json
{
  "requestHeaders": {"content-type": "application/json"},
  "requestBody": "eyJoaSI6MX0=",
  "invocationContext": {
    "requestId": "75269e44-...",
    "apiName": "PetStore",
    "apiVersion": "v1.0.0",
    "method": "POST",
    "path": "/petstore/pets/1",
    "scheme": "https",
    "vhost": "localhost"
  }
}
```

### Reply (`handle-request`)

```json
{
  "directRespond": false,
  "responseCode": 0,
  "headersToAdd":     {"x-trace": "abc-123"},
  "headersToReplace": {"authorization": "Bearer ***"},
  "headersToRemove":  ["x-internal"],
  "pathToRewrite":    "/v2/pets/1?expand=tags",
  "dynamicEndpoint":  {"endpointName": "pets-v2"},
  "body":             "bXV0YXRlZA==",
  "interceptorContext": {"trace": "abc-123"}
}
```

## Reference Scenarios

### 1. Request-only interceptor (PII redaction)

```yaml
apiVersion: gateway.wso2.com/v1alpha1
kind: RestApi
metadata:
  name: chat-api
spec:
  requestPolicies:
    - name: interceptor-service
      version: v0.9
      parameters:
        endpoint: https://pii-redactor:8443/api/v1
        request:
          includeRequestBody: true
          passthroughOnError: false
```

### 2. Direct respond (interceptor short-circuits with 403)

The interceptor returns `{"directRespond": true, "responseCode": 403, "body": "..."}`
to stop the chain and return its own response.

### 3. Path / dynamic-endpoint routing

```yaml
requestPolicies:
  - name: interceptor-service
    version: v0.9
    parameters:
      endpoint: https://router:8443/api/v1
      request:
        includeRequestHeaders: true
```

The interceptor reply may include `pathToRewrite` and/or
`dynamicEndpoint.endpointName` to route the request elsewhere.

### 4. Response-only interceptor (response sanitisation)

```yaml
responsePolicies:
  - name: interceptor-service
    version: v0.9
    parameters:
      endpoint: https://sanitizer:8443/api/v1
      response:
        includeResponseBody: true
        passthroughOnError: true
```

### 5. Round-trip with shared context

Attach the policy in both `requestPolicies` and `responsePolicies`. Any
`interceptorContext` returned by the request-phase interceptor is automatically
echoed in the response-phase request body.

## How It Works

```
client ──► gateway ──► interceptor /handle-request ──► gateway ──► upstream
                                                                       │
client ◄── gateway ◄── interceptor /handle-response ◄── gateway ◄──────┘
```

| Spec field | Gateway action |
| --- | --- |
| `directRespond: true` | `ImmediateResponse{StatusCode, Headers, Body}` |
| `headersToAdd` + `headersToReplace` | `HeadersToSet` (replace wins on conflict) |
| `headersToRemove` | `HeadersToRemove` |
| `body` (base64) | Replaces request/response body |
| `pathToRewrite` | `Path` and `QueryParametersToAdd` |
| `dynamicEndpoint.endpointName` | `UpstreamName` |
| `responseCode` (response phase) | `StatusCode` |
| `interceptorContext` | Stashed in shared metadata under `interceptor-service:context` |
| `trailersTo*` | Ignored (see Limitations) |

## Limitations

- The SDK has no trailer mutation API. `trailersToAdd`, `trailersToReplace`,
  and `trailersToRemove` in the interceptor reply are accepted but **ignored**;
  a debug log is emitted if any are present.
- The wire contract distinguishes `headersToAdd` (append) from
  `headersToReplace` (overwrite). The gateway has no add-vs-replace distinction
  for outbound headers, so both collapse to overwrite. If the same key appears
  in both maps, `headersToReplace` wins.
- Bodies must round-trip through base64. Large bodies cost CPU and bandwidth.
- Interceptor latency is added to request latency (and response latency, when
  the response phase is enabled). Set `timeoutMillis` defensively.
- The policy buffers the body to make it available to the interceptor; do not
  attach it to APIs requiring streaming pass-through.

## Security Considerations

- **TLS.** Always use HTTPS for the interceptor endpoint in production.
  `tlsSkipVerify` exists for development and must not be enabled in production.
- **Authentication.** The policy itself does not authenticate to the
  interceptor. Authenticate at the network layer (mTLS) or via a separate
  policy that injects a bearer token before this policy runs.
- **Input/output size.** Request and response bodies are sent verbatim to the
  interceptor. Combine with body-size guardrail policies to bound the data
  sent.
- **Denial of service.** A slow or hung interceptor can stall the request.
  Set `timeoutMillis` and `passthroughOnError` to match your reliability
  posture.
