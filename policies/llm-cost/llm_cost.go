/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package llmcost

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
)

const (
	// MetadataLLMCost is the SharedContext metadata key for the calculated LLM cost.
	// Value is a USD float formatted to 10 decimal places.
	MetadataLLMCost = "x-llm-cost"

	// MetadataLLMCostStatus indicates whether the cost was successfully calculated.
	// Value is either "calculated" or "not_calculated".
	// This disambiguates x-llm-cost: 0 (which could mean zero cost or a failed calculation).
	MetadataLLMCostStatus = "x-llm-cost-status"

	costStatusCalculated    = "calculated"
	costStatusNotCalculated = "not_calculated"

	// metaKeyAccBody is the metadata key used to accumulate raw bytes for plain
	// JSON (non-SSE) responses delivered via chunked transfer encoding.
	metaKeyAccBody = "x-llm-cost-acc-body"

	// metaKeySSEEvents holds a []json.RawMessage of every parsed SSE event JSON
	// accumulated across streaming chunks. Gives O(1) access to the first and
	// last event without re-scanning raw bytes at EndOfStream.
	metaKeySSEEvents = "x-llm-cost-sse-events"

	// metaKeyIsSSE is set to true once the first SSE chunk is detected. It persists
	// SSE mode across subsequent chunks that may not start with "data: " (e.g. the
	// second half of an event split across two network packets).
	metaKeyIsSSE = "x-llm-cost-is-sse"

	// metaKeyLineRemainder stores an incomplete SSE line fragment from the previous
	// chunk. It is prepended to the next chunk so that events split mid-line across
	// network packets are reconstructed before JSON parsing.
	metaKeyLineRemainder = "x-llm-cost-line-remainder"
)

// LLMCostPolicy calculates the cost of an LLM API call from the response body
// and stores the result in SharedContext.Metadata under "x-llm-cost" (USD float).
type LLMCostPolicy struct {
	pricingMap map[string]ModelPricing
}

var (
	instance     *LLMCostPolicy
	instanceOnce sync.Once
	instanceErr  error
)

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	_ policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	instanceOnce.Do(func() {
		pricingFile, _ := params["pricing_file"].(string)
		if pricingFile == "" {
			instanceErr = fmt.Errorf("llm-cost: pricing_file system parameter is required but not set")
			return
		}
		pm, err := loadPricingFromFile(pricingFile)
		if err != nil {
			instanceErr = fmt.Errorf("llm-cost: failed to load pricing file %q: %w", pricingFile, err)
			return
		}
		slog.Info("llm-cost: pricing map loaded", "path", pricingFile, "entries", len(pm))
		instance = &LLMCostPolicy{pricingMap: pm}
	})
	return instance, instanceErr
}

// Mode declares the SDK processing requirements:
//   - RequestBodyMode=Buffer: buffer the request so ctx.RequestBody is available
//     in OnResponseBody/OnResponseBodyChunk (needed for Anthropic speed parameter).
//   - ResponseBodyMode=Stream: pass each chunk through to the client without
//     kernel-level buffering; we accumulate in metadata and calculate at EndOfStream.
func (p *LLMCostPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestBodyMode:  policy.BodyModeBuffer,
		ResponseBodyMode: policy.BodyModeStream,
	}
}

// OnResponseBody reads the LLM response, looks up model pricing, calculates cost,
// and stores the result in SharedContext.Metadata.
func (p *LLMCostPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if respCtx.ResponseBody == nil || !respCtx.ResponseBody.Present || len(respCtx.ResponseBody.Content) == 0 {
		slog.Warn("llm-cost: empty or missing response body, skipping cost calculation")
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	responseBody := respCtx.ResponseBody.Content

	// If the response body is buffered SSE events, use the same event-array
	// approach as OnResponseBodyChunk so that Anthropic's split usage
	// (input_tokens in message_start, output_tokens in message_delta) is
	// correctly merged by buildAnthropicSSEBody rather than lost by a
	// shallow merge.
	if isSSEContent(responseBody) {
		meta := make(map[string]interface{})
		appendSSEEvents(meta, responseBody)
		events, _ := meta[metaKeySSEEvents].([]json.RawMessage)
		if len(events) == 0 {
			slog.Warn("llm-cost: no valid SSE events found in response body")
			return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
		}
		// Determine provider from the model in events[0] so buildSSEResponseBody
		// can choose the right merge strategy (Anthropic vs others).
		var sseProbe struct {
			Model        string `json:"model"`
			ModelVersion string `json:"modelVersion"`
			Message      *struct {
				Model string `json:"model"`
			} `json:"message"`
		}
		if err := json.Unmarshal(events[0], &sseProbe); err != nil {
			slog.Warn("llm-cost: could not parse first SSE event", "error", err)
			return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
		}
		sseModel := sseProbe.Model
		if sseModel == "" {
			sseModel = sseProbe.ModelVersion
		}
		if sseModel == "" && sseProbe.Message != nil {
			sseModel = sseProbe.Message.Model
		}
		provider := ""
		if sseModel != "" {
			if entry, ok := lookupPricing(p.pricingMap, sseModel); ok {
				provider = entry.Provider
			}
		}
		built, err := buildSSEResponseBody(events, provider)
		if err != nil {
			slog.Warn("llm-cost: failed to build response body from SSE events", "error", err)
			return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
		}
		responseBody = built
	}

	// Extract model name from response body.
	// Providers place the model name in different locations:
	//   $.model        — OpenAI, Anthropic, Mistral (all paths)
	//   $.modelVersion — Gemini
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
		Message      *struct {
			Model string `json:"model"`
		} `json:"message"`
	}
	if err := json.Unmarshal(responseBody, &probe); err != nil {
		slog.Warn("llm-cost: could not parse response body", "error", err)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" && probe.Message != nil {
		modelName = probe.Message.Model
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in response body")
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Look up pricing entry.
	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Select provider calculator.
	calc := selectCalculator(pricing.Provider)
	if calc == nil {
		slog.Warn("llm-cost: unsupported provider, skipping cost calculation", "provider", pricing.Provider, "model", modelName)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Get buffered request body (may be nil for providers that don't need it).
	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	// Normalize provider-specific usage fields into our common Usage struct.
	usage, err := calc.Normalize(responseBody, requestBody)
	if err != nil {
		slog.Warn("llm-cost: failed to normalize usage", "model", modelName, "error", err)
		return setCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	// Calculate base cost using the provider-agnostic generic calculator.
	baseCost := genericCalculateCost(usage, pricing)

	// Apply provider-specific adjustments (geo/speed multipliers, router flat cost, etc.).
	finalCost := calc.Adjust(baseCost, usage, pricing)

	slog.Debug("llm-cost: calculated cost",
		"model", modelName,
		"provider", pricing.Provider,
		"prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens,
		"cost_usd", finalCost,
	)

	return setCostMetadata(respCtx, finalCost, costStatusCalculated)
}

// setCostMetadata writes x-llm-cost and x-llm-cost-status into SharedContext.Metadata
// for the v1alpha2 engine path.
func setCostMetadata(respCtx *policy.ResponseContext, costUSD float64, status string) policy.ResponseAction {
	if respCtx.SharedContext == nil {
		slog.Warn("llm-cost: SharedContext is nil, cannot set cost metadata")
		return policy.DownstreamResponseModifications{}
	}
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}
	respCtx.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", costUSD)
	respCtx.Metadata[MetadataLLMCostStatus] = status
	return policy.DownstreamResponseModifications{
		AnalyticsMetadata: map[string]interface{}{
			MetadataLLMCost: costUSD,
		},
	}
}

// NeedsMoreResponseData implements StreamingResponsePolicy.
// Always returns false — chunks are accumulated in respCtx.Metadata rather than
// held by the kernel, so each chunk flows to the client immediately.
func (p *LLMCostPolicy) NeedsMoreResponseData(_ []byte) bool {
	return false
}

// OnResponseBodyChunk implements StreamingResponsePolicy.
// For SSE responses, each chunk's events are parsed and appended to a
// []json.RawMessage in metadata so the first and last events are cheaply
// accessible at EndOfStream. For plain JSON chunked responses, raw bytes
// are accumulated as usual.
func (p *LLMCostPolicy) OnResponseBodyChunk(_ context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, _ map[string]interface{}) policy.ResponseChunkAction {
	if chunk == nil {
		return policy.ResponseChunkAction{}
	}

	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}

	if len(chunk.Chunk) > 0 {
		// Persist SSE mode once detected: a continuation chunk that starts mid-line
		// (e.g. the second half of an event split across two TCP packets) won't begin
		// with "data: " and would be misrouted to the raw-bytes path without this flag.
		isSSE, _ := respCtx.Metadata[metaKeyIsSSE].(bool)
		if !isSSE && isSSEContent(chunk.Chunk) {
			isSSE = true
			respCtx.Metadata[metaKeyIsSSE] = true
		}
		if isSSE {
			appendSSEEvents(respCtx.Metadata, chunk.Chunk)
		} else {
			prev, _ := respCtx.Metadata[metaKeyAccBody].([]byte)
			respCtx.Metadata[metaKeyAccBody] = append(prev, chunk.Chunk...)
		}
	}

	if !chunk.EndOfStream {
		return policy.ResponseChunkAction{}
	}

	// Flush any line fragment buffered from the last chunk (e.g. a stream that ends
	// without a trailing newline, or an event whose newline arrives in a later packet).
	if remainder, _ := respCtx.Metadata[metaKeyLineRemainder].(string); remainder != "" {
		appendSSEEvents(respCtx.Metadata, []byte("\n"))
	}

	var requestBody []byte
	if respCtx.RequestBody != nil && respCtx.RequestBody.Present {
		requestBody = respCtx.RequestBody.Content
	}

	events, _ := respCtx.Metadata[metaKeySSEEvents].([]json.RawMessage)
	if len(events) > 0 {
		return p.calculateCostFromSSE(respCtx, events, requestBody)
	}

	// Plain JSON path: fall back to raw accumulated bytes.
	responseBody, _ := respCtx.Metadata[metaKeyAccBody].([]byte)
	if len(responseBody) == 0 {
		slog.Warn("llm-cost: empty response body, skipping cost calculation")
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}
	return p.calculateCostFromBody(respCtx, responseBody, requestBody)
}

// calculateCostFromSSE handles the streaming (SSE) path at EndOfStream.
// It extracts the model name from the event array, uses the provider to build
// the appropriate response body from the relevant events, then delegates to
// the shared compute path.
//
// Per-provider event strategy:
//   - OpenAI / Mistral: last event carries model + usage → passed directly.
//   - Gemini / Vertex AI: last event carries modelVersion + usageMetadata → passed directly.
//   - Anthropic: first event (message_start) has model + input tokens inside
//     message envelope; last usage event (message_delta) has output_tokens at
//     top level → merged into a single body.
func (p *LLMCostPolicy) calculateCostFromSSE(respCtx *policy.ResponseStreamContext, events []json.RawMessage, requestBody []byte) policy.ResponseChunkAction {
	// Model name is always present in the first SSE event for all providers:
	//   $.model        — OpenAI, Mistral (every chunk)
	//   $.modelVersion — Gemini (every chunk)
	//   $.message.model — Anthropic message_start (first chunk)
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
		Message      *struct {
			Model string `json:"model"`
		} `json:"message"`
	}
	if err := json.Unmarshal(events[0], &probe); err != nil {
		slog.Warn("llm-cost: could not parse first SSE event", "error", err)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" && probe.Message != nil {
		modelName = probe.Message.Model
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in SSE events")
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	calc := selectCalculator(pricing.Provider)
	if calc == nil {
		slog.Warn("llm-cost: unsupported provider, skipping cost calculation", "provider", pricing.Provider, "model", modelName)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	responseBody, err := buildSSEResponseBody(events, pricing.Provider)
	if err != nil {
		slog.Warn("llm-cost: failed to build response body from SSE events", "error", err)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	return p.computeAndSetCost(respCtx, responseBody, requestBody, modelName, pricing, calc)
}

// calculateCostFromBody handles the plain JSON (non-SSE) path at EndOfStream.
// Extracts the model name from the body, looks up pricing, and delegates to the
// shared compute path.
func (p *LLMCostPolicy) calculateCostFromBody(respCtx *policy.ResponseStreamContext, responseBody []byte, requestBody []byte) policy.ResponseChunkAction {
	var probe struct {
		Model        string `json:"model"`
		ModelVersion string `json:"modelVersion"`
		Message      *struct {
			Model string `json:"model"`
		} `json:"message"`
	}
	if err := json.Unmarshal(responseBody, &probe); err != nil {
		slog.Warn("llm-cost: could not parse response body", "error", err)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}
	modelName := probe.Model
	if modelName == "" {
		modelName = probe.ModelVersion
	}
	if modelName == "" && probe.Message != nil {
		modelName = probe.Message.Model
	}
	if modelName == "" {
		slog.Warn("llm-cost: no model name found in response body")
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	pricing, found := lookupPricing(p.pricingMap, modelName)
	if !found {
		slog.Warn("llm-cost: no pricing entry for model, setting cost to 0", "model", modelName)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	calc := selectCalculator(pricing.Provider)
	if calc == nil {
		slog.Warn("llm-cost: unsupported provider, skipping cost calculation", "provider", pricing.Provider, "model", modelName)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	return p.computeAndSetCost(respCtx, responseBody, requestBody, modelName, pricing, calc)
}

// computeAndSetCost normalizes usage from responseBody, calculates the final
// cost, and stores the result in SharedContext.Metadata.
func (p *LLMCostPolicy) computeAndSetCost(respCtx *policy.ResponseStreamContext, responseBody []byte, requestBody []byte, modelName string, pricing ModelPricing, calc providerCalculator) policy.ResponseChunkAction {
	usage, err := calc.Normalize(responseBody, requestBody)
	if err != nil {
		slog.Warn("llm-cost: failed to normalize usage", "model", modelName, "error", err)
		return setStreamCostMetadata(respCtx, 0.0, costStatusNotCalculated)
	}

	baseCost := genericCalculateCost(usage, pricing)
	finalCost := calc.Adjust(baseCost, usage, pricing)

	slog.Debug("llm-cost: calculated cost",
		"model", modelName,
		"provider", pricing.Provider,
		"prompt_tokens", usage.PromptTokens,
		"completion_tokens", usage.CompletionTokens,
		"cost_usd", finalCost,
	)

	return setStreamCostMetadata(respCtx, finalCost, costStatusCalculated)
}

// isSSEContent reports whether the body looks like buffered SSE data (has at
// least one "data: " line).
func isSSEContent(b []byte) bool {
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// mergeSSEEvents parses every SSE data/event line as JSON and shallow-merges all
// top-level keys into a single object (later events win). This produces a
// JSON blob that contains the `model` from early events together with the
// `usage` / `usageMetadata` from the final event, allowing existing
// provider calculators to parse it unchanged.
// The "usage" and "usageMetadata" keys are deep-merged so that fields
// from earlier events (e.g. input_tokens) survive when a later event
// only carries output_tokens.
func mergeSSEEvents(body []byte) ([]byte, error) {
	merged := make(map[string]interface{})

	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		var value string
		if strings.HasPrefix(line, sseDataPrefix) {
			value = strings.TrimPrefix(line, sseDataPrefix)
		} else if strings.HasPrefix(line, sseEventPrefix) {
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		} else {
			continue
		}
		value = strings.TrimSpace(value)
		if value == sseDone || value == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(value), &event); err != nil {
			continue // skip non-JSON lines
		}

		for k, v := range event {
			// Deep-merge "usage" and "usageMetadata" maps so that fields
			// from earlier events (e.g. input_tokens) survive when a later
			// event only carries output_tokens.
			if (k == "usage" || k == "usageMetadata") && v != nil {
				if newMap, ok := v.(map[string]interface{}); ok {
					if existing, ok := merged[k].(map[string]interface{}); ok {
						for ek, ev := range newMap {
							existing[ek] = ev
						}
						continue
					}
				}
			}
			merged[k] = v
		}
	}

	if len(merged) == 0 {
		return nil, fmt.Errorf("no valid SSE events found")
	}

	return json.Marshal(merged)
}

// appendSSEEvents parses the SSE lines in chunk, validates each as JSON, and
// appends them to the []json.RawMessage slice stored at metadata[metaKeySSEEvents].
//
// It maintains a line-remainder buffer so that SSE events split mid-line across
// network packets are reconstructed before JSON parsing. A chunk that does not end
// with '\n' leaves the trailing fragment in metadata[metaKeyLineRemainder]; that
// fragment is prepended to the next call's data automatically.
func appendSSEEvents(metadata map[string]interface{}, chunk []byte) {
	// Reconstruct any fragment that was left over from the previous chunk.
	remainder, _ := metadata[metaKeyLineRemainder].(string)
	data := remainder + string(chunk)

	events, _ := metadata[metaKeySSEEvents].([]json.RawMessage)

	lines := strings.Split(data, "\n")

	// If data doesn't end with '\n' the last element is an incomplete line;
	// save it for the next chunk rather than attempting to parse it now.
	newRemainder := ""
	completeLines := lines
	if !strings.HasSuffix(data, "\n") && len(lines) > 0 {
		newRemainder = lines[len(lines)-1]
		completeLines = lines[:len(lines)-1]
	}

	for _, line := range completeLines {
		line = strings.TrimRight(line, "\r")
		var value string
		if strings.HasPrefix(line, sseDataPrefix) {
			value = strings.TrimPrefix(line, sseDataPrefix)
		} else if strings.HasPrefix(line, sseEventPrefix) {
			value = strings.TrimSpace(strings.TrimPrefix(line, sseEventPrefix))
		} else {
			continue
		}
		value = strings.TrimSpace(value)
		if value == sseDone || value == "" {
			continue
		}
		if json.Valid([]byte(value)) {
			events = append(events, json.RawMessage(value))
		}
	}

	metadata[metaKeySSEEvents] = events
	metadata[metaKeyLineRemainder] = newRemainder
}

// buildSSEResponseBody constructs a JSON body suitable for the provider's
// Normalize() method from the accumulated SSE events.
//
//   - OpenAI / Mistral / Gemini / Vertex AI: the last event already contains
//     model + usage (or usageMetadata), so it is returned as-is.
//   - Anthropic: usage is split across events — input tokens are inside the
//     message envelope of the first event, output tokens are at the top level
//     of the last message_delta event. buildAnthropicSSEBody merges them.
func buildSSEResponseBody(events []json.RawMessage, provider string) ([]byte, error) {
	if provider == "anthropic" {
		return buildAnthropicSSEBody(events)
	}
	// OpenAI, Mistral, Gemini, Vertex AI: last event has everything needed.
	return events[len(events)-1], nil
}

// buildAnthropicSSEBody constructs the body for AnthropicCalculator.Normalize()
// from the event array. It seeds the usage map from the first event's
// message.usage (input_tokens, cache tokens) and then overlays the last
// event that carries a top-level usage key (message_delta's output_tokens).
func buildAnthropicSSEBody(events []json.RawMessage) ([]byte, error) {
	// First event (message_start) carries model + input usage inside message envelope.
	var startEvent struct {
		Message *struct {
			Model string          `json:"model"`
			Usage json.RawMessage `json:"usage"`
		} `json:"message"`
	}
	if err := json.Unmarshal(events[0], &startEvent); err != nil || startEvent.Message == nil {
		return nil, fmt.Errorf("anthropic: missing or unparseable message_start event")
	}

	// Seed usage from message_start.message.usage (input_tokens, cache tokens, etc.).
	usage := make(map[string]interface{})
	if len(startEvent.Message.Usage) > 0 {
		_ = json.Unmarshal(startEvent.Message.Usage, &usage)
	}

	// Overlay with the last event that has a non-empty top-level usage
	// (message_delta carries output_tokens and optionally inference_geo).
	for i := len(events) - 1; i >= 0; i-- {
		var probe struct {
			Usage json.RawMessage `json:"usage"`
		}
		if err := json.Unmarshal(events[i], &probe); err != nil || len(probe.Usage) <= 2 {
			continue
		}
		var deltaUsage map[string]interface{}
		if err := json.Unmarshal(probe.Usage, &deltaUsage); err == nil {
			for k, v := range deltaUsage {
				usage[k] = v
			}
		}
		break
	}

	return json.Marshal(map[string]interface{}{
		"model": startEvent.Message.Model,
		"usage": usage,
	})
}

// setStreamCostMetadata writes x-llm-cost and x-llm-cost-status into
// SharedContext.Metadata and returns a ResponseChunkAction with AnalyticsMetadata.
func setStreamCostMetadata(respCtx *policy.ResponseStreamContext, costUSD float64, status string) policy.ResponseChunkAction {
	if respCtx.SharedContext == nil {
		slog.Warn("llm-cost: SharedContext is nil, cannot set cost metadata")
		return policy.ResponseChunkAction{}
	}
	if respCtx.Metadata == nil {
		respCtx.Metadata = make(map[string]interface{})
	}
	respCtx.Metadata[MetadataLLMCost] = fmt.Sprintf("%.10f", costUSD)
	respCtx.Metadata[MetadataLLMCostStatus] = status
	return policy.ResponseChunkAction{
		AnalyticsMetadata: map[string]interface{}{
			MetadataLLMCost: costUSD,
		},
	}
}
