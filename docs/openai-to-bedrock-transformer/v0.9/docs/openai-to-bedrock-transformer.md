---
title: "Overview"
---
# OpenAI to Bedrock Transformer

## Overview

The OpenAI to Bedrock Transformer policy lets OpenAI Chat Completions clients use the AWS Bedrock Converse API without changing their request or response handling. It rewrites requests to Bedrock's `/model/{modelId}/converse` or `/model/{modelId}/converse-stream` endpoint and translates Bedrock responses back to the OpenAI format.

The policy supports two modes:

- **Single-provider mode** — attach the transformer directly to a proxy. When no provider is selected in request metadata, it always runs.
- **Multi-provider mode** — attach the transformer to an additional Bedrock provider. It runs only when `SharedContext.Metadata["selected_provider"]` matches its provider `id`.

## Features

- Converts OpenAI messages, system/developer prompts, inference settings, stop sequences, and tools to Bedrock Converse format.
- Maps OpenAI assistant tool calls and tool results to Bedrock `toolUse` and `toolResult` content blocks.
- Supports base64 data-URI images in OpenAI `image_url` blocks.
- Rewrites non-streaming Converse responses, usage, tool calls, finish reasons, and errors to OpenAI ChatCompletion JSON.
- Decodes Bedrock's binary Amazon event-stream responses and emits OpenAI-compatible Server-Sent Events, including usage and the final `[DONE]` marker.
- Supports Bedrock model IDs and inference-profile IDs in the upstream path.

## Parameters

| Name | Required | Default | Description |
|------|----------|---------|-------------|
| `model` | Yes | — | Bedrock model or inference-profile ID placed in the Converse request path. |
| `id` | No | — | Target provider ID. It is also used as the upstream name and matched against the selected provider in multi-provider mode. |
| `maxTokens` | No | `4096` | Fallback `inferenceConfig.maxTokens` when the OpenAI request omits both `max_completion_tokens` and `max_tokens`. |

## Example

For a multi-provider LLM proxy, attach the transformer to the Bedrock provider. The provider `id` is supplied by the gateway, so it is not repeated in `params`:

```yaml
additionalProviders:
  - id: bedrock-provider
    auth:
      type: api-key
      header: Authorization
      value: Bearer REPLACE_WITH_BEDROCK_API_KEY
    transformer:
      type: openai-to-bedrock-transformer
      version: v1
      params:
        model: us.anthropic.claude-sonnet-4-5-20250929-v1:0
        maxTokens: 4096
```

For a single-provider proxy, attach the policy directly:

```yaml
policies:
  - name: openai-to-bedrock-transformer
    version: v1
    paths:
      - path: /chat/completions
        methods: [POST]
        params:
          model: us.amazon.nova-lite-v1:0
```

## Notes

- The policy translates payloads and paths only. Configure Bedrock authentication on the upstream provider.
- Remote image URLs are not fetched; use base64 data URIs for image input.
- Streaming translation expects Bedrock's `application/vnd.amazon.eventstream` framing.
