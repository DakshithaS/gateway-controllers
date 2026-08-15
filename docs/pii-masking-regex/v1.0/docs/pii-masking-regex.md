---
title: "Overview"
---
# PII Masking Regex Guardrail

## Overview

The PII Masking Regex Guardrail masks or redacts Personally Identifiable Information (PII) from request and response bodies using configurable regular expression patterns. This guardrail helps protect sensitive user data by replacing PII with placeholders or redaction markers before content is processed or returned.

This policy supports SSE streaming responses. When the upstream returns a streaming response (`stream: true`), the guardrail detects PII placeholders in the streamed assistant text and restores masked values across event and chunk boundaries. It is not tied to one vendor's wire format: the OpenAI chat/legacy completions shape (and every provider that speaks it), Anthropic Messages, Google Gemini, and Amazon Bedrock are handled out of the box, with no configuration required.

## Features

- Configurable PII entity detection using regular expressions
- Two modes: masking (reversible) and redaction (permanent)
- Automatic PII restoration in responses when using masking mode
- Supports JSONPath extraction to process specific fields within JSON payloads
- Streaming response support for both SSE and plain chunked bodies -- withholds only the trailing bytes that could still complete a PII placeholder (e.g., `[EMAIL_0000]`), never the whole response

## Configuration

This policy requires only a single-level configuration where all parameters are configured in the API definition YAML.

### User Parameters (API Definition)

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `email` | boolean | No | `false` | Enables built-in EMAIL detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `phone` | boolean | No | `false` | Enables built-in PHONE detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `ssn` | boolean | No | `false` | Enables built-in SSN detection. At least one of `email`, `phone`, `ssn`, or `customPIIEntities` must be enabled. |
| `customPIIEntities` | `CustomPIIEntity` array | No | - | Custom PII entity definitions for detection. Each item defines a `piiEntity` name and `piiRegex` pattern. At least one item required if provided. |
| `jsonPath` | string | No | `"$.messages[-1].content"` | JSONPath expression to extract a specific value from JSON payload. If empty, processes the entire payload as a string. |
| `redactPII` | boolean | No | `false` | If `true`, redacts PII by replacing with "*****" (permanent, cannot be restored). If `false`, masks PII with placeholders that can be restored in responses. |

### CustomPIIEntity Configuration

Each item in the `customPIIEntities` array must contain:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `piiEntity` | string | Yes | Name/type of the PII entity (e.g., "CREDIT_CARD", "PASSPORT"). Must contain only uppercase letters and underscores. |
| `piiRegex` | string | Yes | Regular expression pattern to match the PII entity. Must be a valid Go regexp pattern. |

#### Supported Streaming Response Shapes

In a streaming response the assistant text is located by trying a list of JSONPath expressions in
order against each SSE `data:` frame; the first match wins. One policy configuration therefore works
across providers with different wire formats.

Multiple shapes are needed because the `openai-to-*` transformer policies deliberately do **not**
translate streaming responses: `openai-to-anthropic-transformer` and `openai-to-gemini-transformer`
pass SSE through untouched (streaming translation would require a stateful chunk-level policy), so
this policy sees provider-native Anthropic and Gemini frames rather than a normalized OpenAI shape.
`openai-to-bedrock-transformer` is the exception — it decodes the Amazon binary event-stream into
OpenAI chunks, so Bedrock traffic arrives already OpenAI-shaped.

| JSONPath | Covers |
|----------|--------|
| `$.choices[0].delta.content` | OpenAI chat completions — also Azure OpenAI, Mistral, Groq, DeepSeek, Together, Fireworks, and any other OpenAI-compatible provider |
| `$.delta.text` | Anthropic Messages (`content_block_delta`) |
| `$.candidates[0].content.parts[0].text` | Google Gemini `streamGenerateContent` |
| `$.contentBlockDelta.delta.text` | Amazon Bedrock Converse |
| `$.outputText` | Amazon Bedrock (Titan) |
| `$.completion` | Anthropic legacy text completions |
| `$.choices[0].text` | OpenAI legacy completions |
| `$.delta` | OpenAI Responses API `/responses` (also Azure OpenAI and Azure AI Foundry), where `response.output_text.delta` carries the text as a plain string |

`$.delta` is deliberately last: it is the most generic shape in the list, so every more specific path
gets first refusal. It cannot shadow Anthropic's `$.delta.text`, because Anthropic's `delta` is an
object and only scalar values resolve to text.

A frame matching none of these is forwarded unchanged, which means a provider whose streaming shape is
not listed will deliver the masked placeholder rather than the restored value. Support for a new
format is added by extending this list in the policy.

Restoration in **non-streaming** responses is format-independent — placeholders are replaced directly
in the raw JSON bytes — so a buffered response from any provider is restored regardless of shape.

#### JSONPath Support

The guardrail supports JSONPath expressions to extract and process specific fields within JSON payloads. Common examples:

- `$.messages` - Extracts the `messages` field from the root object
- `$.data.content` - Extracts nested content from `data.content`
- `$.items[0].text` - Extracts text from the first item in an array
- `$.messages[0].content` - Extracts content from the first message in a messages array

If `jsonPath` is empty or not specified, the entire payload is processed as a string.

**Note:**

Inside the `gateway/build.yaml`, ensure the policy module is added under `policies:`:

```yaml
- name: pii-masking-regex
  gomodule: github.com/wso2/gateway-controllers/policies/pii-masking-regex@v1
```

## Reference Scenarios

### Example 1: Basic PII Masking

Deploy an LLM provider that masks email addresses and phone numbers in requests and restores them in responses:

```yaml
apiVersion: gateway.api-platform.wso2.com/v1
kind: LlmProvider
metadata:
  name: pii-masking-provider
spec:
  displayName: PII Masking Provider
  version: v1.0
  template: openai
  context: /openai
  upstream:
    url: "https://api.openai.com/v1"
    auth:
      type: api-key
      header: Authorization
      value: Bearer <openai-apikey>
  accessControl:
    mode: deny_all
    exceptions:
      - path: /chat/completions
        methods: [POST]
      - path: /models
        methods: [GET]
      - path: /models/{modelId}
        methods: [GET]
  operationPolicies:
    - name: pii-masking-regex
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            email: true
            phone: true
            jsonPath: "$.messages[-1].content"
            redactPII: true
```

**Test the guardrail:**

```bash
# Request with PII (should be masked)
curl -X POST http://localhost:8080/openai/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4",
    "messages": [
      {
        "role": "user",
        "content": "Contact me at john.doe@example.com or call +1234567890"
      }
    ]
  }'
```

 **Sample Payload after intervention from Regex PII Masking with redactPII=true**

```json
{
  "messages": [
    {
      "role": "user",
      "content": "Prepare an email with my contact information, email: *****, and website: https://example.com."
    }
  ]
}
```

### Example 2: Streaming Response PII Restoration

When using masking mode with a streaming LLM endpoint, PII placeholders sent to the upstream are automatically restored in the SSE response stream:

```yaml
  operationPolicies:
    - name: pii-masking-regex
      version: v1
      paths:
        - path: /chat/completions
          methods: [POST]
          params:
            email: true
            phone: true
            jsonPath: "$.messages[-1].content"
            redactPII: false
```

When the upstream returns an SSE streaming response, the policy detects placeholders such as `[EMAIL_0000]` in the delta content across chunk boundaries and restores them to the original PII values. The smart boundary detection ensures placeholders split across multiple SSE events (e.g., `[`, `EMAIL`, `_`, `0000`, `]` arriving in separate tokens) are correctly reassembled before restoration.

## How It Works

#### Request Phase

1. **Content Extraction**: Extracts content using `jsonPath` (if configured) or uses the entire payload as a string.
2. **PII Detection**: Applies each configured `piiRegex` pattern to detect matching PII entities.
3. **Intervention**: Replaces matches with placeholders (`[ENTITY_TYPE_XXXX]`) in masking mode or with `*****` in redaction mode.
4. **Metadata Storage**: Stores placeholder-to-original mappings in request metadata when masking mode is used.
5. **Forwarding**: Sends the transformed payload to the upstream service.

#### Response Phase

1. **Mapping Check**: Checks whether masking metadata is available from request processing.
2. **Restoration**: If `redactPII: false`, replaces placeholders with original values in the response.
3. **Redaction Preservation**: If `redactPII: true`, no restoration is performed.
4. **Response Return**: Returns restored or redacted content to the client.

#### PII Modes

- **Masking Mode (`redactPII: false`)**: Uses placeholders such as `[EMAIL_0000]` and original PII values are stored temporarily in request metadata for restoration. Recommended when you need to preserve data for downstream processing or response generation
- **Redaction Mode (`redactPII: true`)**: Permanently replaces detected PII with `*****` and does not restore original values. Recommended for maximum privacy protection when original values are not needed

### Streaming (SSE) Processing

When the upstream returns an SSE streaming response, each SSE event arrives as a `data:` line containing a JSON payload, for example:

```
data: {"choices":[{"delta":{"content":"token"}}]}
```

The PII masking policy restores masked placeholders in streaming responses using placeholder-prefix boundary detection:

1. **Response Mode Detection**: The response is routed as SSE or plain-body once per request, based on the upstream `Content-Type` (`text/event-stream`). The decision is sticky, so an event that is legitimately not data-shaped — a `: keep-alive` comment, for example — never reroutes the stream.
2. **Delta Content Extraction**: Content is extracted from `choices[*].delta.content` in each SSE `data:` line.
3. **Placeholder Boundary Detection**: Events are held only while the tail of their concatenated delta content is a prefix of a placeholder actually masked in this request (`[EMA` when `[EMAIL_0000]` was masked). The hold is released as soon as the placeholder completes, the tail stops matching, `[DONE]` arrives, or the stream ends — so a placeholder split across any number of events is restored, and a `[` in ordinary prose never withholds anything.
4. **Placeholder Restoration**: When a held run resolves, all `delta.content` values are concatenated, placeholders are restored to their original PII values, and the restored text is placed into the first content-bearing SSE event while subsequent merged events are dropped. Comments, `[DONE]`, and usage frames keep their original position.
5. **Redaction Mode**: When `redactPII: true`, no restoration is performed in the response phase, so streaming chunks pass through without buffering.
6. **Error Handling**: Since HTTP response headers are already committed when streaming begins, errors cannot be reported via HTTP status codes. If an error occurs during restoration, the chunk passes through unmodified.

**Non-SSE chunked responses**: For plain JSON responses delivered via chunked transfer encoding (e.g., `stream: false` with `Transfer-Encoding: chunked`), chunks are restored and forwarded as they arrive. Only the shortest trailing run of bytes that could still grow into a placeholder is withheld, so the whole body is never buffered and the response streams through without added latency.

**Compressed responses**: `gzip` and `br` responses are decompressed by the gateway before this policy runs and re-compressed afterwards, so restoration works normally. Responses in an encoding the gateway cannot round-trip (for example `deflate` or `zstd`) are forwarded untouched and are **not** inspected or restored — the gateway logs a warning when this happens.

#### Processing Behavior

- Supports multiple entity patterns in one policy and processes each detected match by entity type.
- Placeholder format is `[ENTITY_TYPE_XXXX]`, where `XXXX` is a 4-digit hexadecimal sequence.
- Full payload processing is used when `jsonPath` is not configured.

## Notes

- Common use cases include privacy protection, compliance (GDPR/CCPA/HIPAA), data minimization, secure AI processing, and audit-friendly masking workflows.
- Regular expressions use Go's regexp package (RE2 syntax).
- PII detection is case-sensitive by default. Use `(?i)` flag for case-insensitive matching.
- The `piiEntity` name must contain only uppercase letters and underscores (e.g., "EMAIL", "PHONE_NUMBER", "SSN").
- When using masking mode, the placeholder-to-original mapping is stored in request metadata and automatically used for response restoration.
- Multiple PII entities can match the same content; each match is processed according to its entity type.
- Placeholder format is `[ENTITY_TYPE_XXXX]` where XXXX is a 4-digit hexadecimal number (e.g., `[EMAIL_0000]`, `[EMAIL_0001]`, `[PHONE_000a]`).
- When using JSONPath, if the path does not exist or the extracted value is not a string, an error response (HTTP 500) is returned.
- Redaction mode is irreversible; use masking mode if you need to restore PII in responses.
- In streaming mode, `redactPII: true` disables response-phase processing entirely since there is nothing to restore. Chunks pass through without buffering overhead.
- In streaming mode, placeholder boundary detection buffers up to 5 additional SSE data lines when an unclosed `[` is found. This prevents false negatives from placeholders split across SSE event boundaries.
- Complex regex patterns may impact performance; test thoroughly with expected content volumes.
