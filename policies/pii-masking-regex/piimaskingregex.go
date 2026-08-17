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

package piimaskingregex

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
	utils "github.com/wso2/api-platform/sdk/core/utils"
)

const (
	APIMInternalErrorCode     = 500
	APIMInternalExceptionCode = 900967
	TextCleanRegex            = "^\"|\"$"
	MetadataKeyPIIEntities    = "piimaskingregex:pii_entities"
	DefaultEmailEntityName    = "EMAIL"
	DefaultPhoneEntityName    = "PHONE"
	DefaultSSNEntityName      = "SSN"
	DefaultJSONPath           = "$.messages[-1].content"
	DefaultEmailRegex         = `(?i)\b[a-z0-9.!#$%&'*+/=?^_{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])\b`
	DefaultPhoneRegex         = `(?:\+?1[-.\s]?)?(?:\([2-9][0-9]{2}\)|[2-9][0-9]{2})[-.\s]?[2-9][0-9]{2}[-.\s]?[0-9]{4}\b`
	DefaultSSNRegex           = `(?:00[1-9]|0[1-9][0-9]|[1-5][0-9]{2}|6(?:[0-57-9][0-9]|6[0-57-9])|[7-8][0-9]{2})[- ]?(?:0[1-9]|[1-9][0-9])[- ]?(?:000[1-9]|00[1-9][0-9]|0[1-9][0-9]{2}|[1-9][0-9]{3})\b`

	// SSE constants for streaming responses
	sseDataPrefix  = "data: "
	sseDone        = "[DONE]"
	sseEventPrefix = "event:"
)

// DefaultStreamingJSONPaths locate the assistant text inside one SSE data frame.
// They are tried in order and the first match wins, so this policy is not bound
// to any single vendor's wire format. A shape that is not listed here is not
// restored: the frame passes through untouched and the client sees the masked
// placeholder, so a new provider format is added by extending this list.
var DefaultStreamingJSONPaths = []string{
	// OpenAI chat completions — also Azure OpenAI, Mistral, Groq, DeepSeek,
	// Together, Fireworks and everything else speaking the OpenAI wire format.
	"$.choices[0].delta.content",
	// Anthropic Messages — content_block_delta carries delta.text.
	"$.delta.text",
	// Google Gemini streamGenerateContent.
	"$.candidates[0].content.parts[0].text",
	// Amazon Bedrock Converse — contentBlockDelta wraps the same delta.text.
	"$.contentBlockDelta.delta.text",
	// Amazon Bedrock (Titan) and Anthropic legacy text completions.
	"$.outputText",
	"$.completion",
	// OpenAI legacy completions.
	"$.choices[0].text",
	// OpenAI Responses API (also Azure OpenAI and Azure AI Foundry /responses)
	// — response.output_text.delta carries the text as a plain string, not an
	// object. Last on purpose: it is the most generic shape here, so every
	// specific path above gets first refusal. Anthropic's delta is an object,
	// and ExtractStringValueFromJsonpath errors on non-scalars, so this cannot
	// steal a match from "$.delta.text".
	"$.delta",
}

var textCleanRegexCompiled = regexp.MustCompile(TextCleanRegex)

// PIIMaskingRegexPolicy implements regex-based PII masking
type PIIMaskingRegexPolicy struct {
	params PIIMaskingRegexPolicyParams
}

type PIIMaskingRegexPolicyParams struct {
	PIIEntities map[string]*regexp.Regexp
	JsonPath    string
	RedactPII   bool
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	p := &PIIMaskingRegexPolicy{}

	// Parse parameters.
	policyParams, err := parseParams(params)
	if err != nil {
		return nil, fmt.Errorf("invalid parameters: %w", err)
	}
	p.params = policyParams

	return p, nil
}

// Mode returns the processing mode for the PII masking regex policy.
func (p *PIIMaskingRegexPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeStream,
	}
}

// parseParams parses and validates parameters from map to struct.
func parseParams(params map[string]interface{}) (PIIMaskingRegexPolicyParams, error) {
	var result PIIMaskingRegexPolicyParams
	result.JsonPath = DefaultJSONPath
	piiEntities := make(map[string]*regexp.Regexp)

	// Extract customPIIEntities parameter if provided.
	piiEntitiesRaw, ok := params["customPIIEntities"]
	if ok {
		// Parse custom PII entities.
		var piiEntitiesArray []map[string]interface{}
		switch v := piiEntitiesRaw.(type) {
		case string:
			if err := json.Unmarshal([]byte(v), &piiEntitiesArray); err != nil {
				return result, fmt.Errorf("error unmarshaling PII entities: %w", err)
			}
		case []interface{}:
			piiEntitiesArray = make([]map[string]interface{}, 0, len(v))
			for idx, item := range v {
				if itemMap, ok := item.(map[string]interface{}); ok {
					piiEntitiesArray = append(piiEntitiesArray, itemMap)
				} else {
					return result, fmt.Errorf("'customPIIEntities[%d]' must be an object", idx)
				}
			}
		default:
			return result, fmt.Errorf("'customPIIEntities' must be an array or JSON string")
		}

		// Validate each custom PII entity.
		for i, entityConfig := range piiEntitiesArray {
			piiEntity, ok := entityConfig["piiEntity"].(string)
			if !ok || strings.TrimSpace(piiEntity) == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' is required and must be a non-empty string", i)
			}

			normalizedPIIEntity := strings.ToUpper(strings.TrimSpace(piiEntity))
			if !regexp.MustCompile(`^[A-Z_]+$`).MatchString(normalizedPIIEntity) {
				return result, fmt.Errorf("'customPIIEntities[%d].piiEntity' must contain only letters and underscores", i)
			}

			piiRegex, ok := entityConfig["piiRegex"].(string)
			if !ok || piiRegex == "" {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is required and must be a non-empty string", i)
			}

			compiledPattern, err := regexp.Compile(piiRegex)
			if err != nil {
				return result, fmt.Errorf("'customPIIEntities[%d].piiRegex' is invalid: %w", i, err)
			}

			if _, exists := piiEntities[normalizedPIIEntity]; exists {
				return result, fmt.Errorf("duplicate piiEntity: %q", normalizedPIIEntity)
			}
			piiEntities[normalizedPIIEntity] = compiledPattern
		}
	}

	// Extract built-in entity toggles.
	enableEmail, err := parseBoolParam(params, "email")
	if err != nil {
		return result, err
	}
	enablePhone, err := parseBoolParam(params, "phone")
	if err != nil {
		return result, err
	}
	enableSSN, err := parseBoolParam(params, "ssn")
	if err != nil {
		return result, err
	}

	if enableEmail {
		if _, exists := piiEntities[DefaultEmailEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultEmailEntityName)
		}
		piiEntities[DefaultEmailEntityName] = regexp.MustCompile(DefaultEmailRegex)
	}
	if enablePhone {
		if _, exists := piiEntities[DefaultPhoneEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultPhoneEntityName)
		}
		piiEntities[DefaultPhoneEntityName] = regexp.MustCompile(DefaultPhoneRegex)
	}
	if enableSSN {
		if _, exists := piiEntities[DefaultSSNEntityName]; exists {
			return result, fmt.Errorf("duplicate piiEntity: %q", DefaultSSNEntityName)
		}
		piiEntities[DefaultSSNEntityName] = regexp.MustCompile(DefaultSSNRegex)
	}

	if len(piiEntities) == 0 {
		return result, fmt.Errorf("at least one PII detector must be configured using 'customPIIEntities' or one of 'email', 'phone', 'ssn'")
	}
	result.PIIEntities = piiEntities

	// Extract optional jsonPath parameter
	if jsonPathRaw, ok := params["jsonPath"]; ok {
		if jsonPath, ok := jsonPathRaw.(string); ok {
			result.JsonPath = jsonPath
		} else {
			return result, fmt.Errorf("'jsonPath' must be a string")
		}
	}

	// Extract optional redactPII parameter
	if redactPIIRaw, ok := params["redactPII"]; ok {
		if redactPII, ok := redactPIIRaw.(bool); ok {
			result.RedactPII = redactPII
		} else {
			return result, fmt.Errorf("'redactPII' must be a boolean")
		}
	}

	return result, nil
}

func parseBoolParam(params map[string]interface{}, key string) (bool, error) {
	valRaw, ok := params[key]
	if !ok {
		return false, nil
	}
	val, ok := valRaw.(bool)
	if !ok {
		return false, fmt.Errorf("'%s' must be a boolean", key)
	}
	return val, nil
}

// maskPIIFromContent masks PII from content using regex patterns
func (p *PIIMaskingRegexPolicy) maskPIIFromContent(content string, piiEntities map[string]*regexp.Regexp, metadata map[string]interface{}) (string, error) {
	if content == "" {
		return "", nil
	}

	maskedContent := content
	maskedPIIEntities := make(map[string]string)
	counter := 0
	// Pre-compile placeholder pattern for efficiency
	placeholderPattern := regexp.MustCompile(`^\[[A-Z_]+_[0-9a-f]{4}\]$`)

	// First pass: find all matches without replacing to avoid nested replacements
	allMatches := make(map[string]string) // original -> placeholder
	for key, pattern := range piiEntities {
		matches := pattern.FindAllString(maskedContent, -1)
		for _, match := range matches {
			if _, exists := allMatches[match]; !exists && !placeholderPattern.MatchString(match) {
				// Generate unique placeholder like [EMAIL_0000]
				placeholder := fmt.Sprintf("[%s_%04x]", key, counter)
				allMatches[match] = placeholder
				maskedPIIEntities[match] = placeholder
				counter++
			}
		}
	}

	// Second pass: replace all matches
	originals := make([]string, 0, len(allMatches))
	for original := range allMatches {
		originals = append(originals, original)
	}
	sort.Slice(originals, func(i, j int) bool { return len(originals[i]) > len(originals[j]) })
	for _, original := range originals {
		maskedContent = strings.ReplaceAll(maskedContent, original, allMatches[original])
	}

	// Store PII mappings in metadata for response restoration
	if len(maskedPIIEntities) > 0 {
		metadata[MetadataKeyPIIEntities] = maskedPIIEntities
	}

	if len(allMatches) > 0 {
		return maskedContent, nil
	}

	return "", nil
}

// redactPIIFromContent redacts PII from content using regex patterns
func (p *PIIMaskingRegexPolicy) redactPIIFromContent(content string, piiEntities map[string]*regexp.Regexp) string {
	if content == "" {
		return ""
	}

	maskedContent := content
	foundAndMasked := false

	for _, pattern := range piiEntities {
		if pattern.MatchString(maskedContent) {
			foundAndMasked = true
			maskedContent = pattern.ReplaceAllString(maskedContent, "*****")
		}
	}

	if foundAndMasked {
		return maskedContent
	}

	return ""
}

// restorePIIInResponse handles PII restoration in responses when redactPII is disabled
func (p *PIIMaskingRegexPolicy) restorePIIInResponse(originalContent string, maskedPIIEntities map[string]string) string {
	if len(maskedPIIEntities) == 0 {
		return originalContent
	}

	transformedContent := originalContent

	for original, placeholder := range maskedPIIEntities {
		if strings.Contains(transformedContent, placeholder) {
			transformedContent = strings.ReplaceAll(transformedContent, placeholder, original)
		}
	}

	return transformedContent
}

// updatePayloadWithMaskedContent updates the original payload by replacing the extracted content
func (p *PIIMaskingRegexPolicy) updatePayloadWithMaskedContent(originalPayload []byte, extractedValue, modifiedContent string, jsonPath string) []byte {
	if jsonPath == "" {
		// If no JSONPath, the entire payload was processed, return the modified content
		return []byte(modifiedContent)
	}

	// If JSONPath is specified, update only the specific field in the JSON structure
	var jsonData map[string]interface{}
	if err := json.Unmarshal(originalPayload, &jsonData); err != nil {
		// Fallback to returning the modified content as-is
		return []byte(modifiedContent)
	}

	// Set the new value at the JSONPath location
	err := utils.SetValueAtJSONPath(jsonData, jsonPath, modifiedContent)
	if err != nil {
		// Fallback to returning the original payload
		return originalPayload
	}

	// Marshal back to JSON to get the full modified payload
	updatedPayload, err := json.Marshal(jsonData)
	if err != nil {
		// Fallback to returning the original payload
		return originalPayload
	}

	return updatedPayload
}

// OnRequestHeaders implements v2alpha.RequestHeaderPolicy.
// PII masking operates on the body, so headers are passed through unchanged.
func (p *PIIMaskingRegexPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	return policy.UpstreamRequestHeaderModifications{}
}

// OnResponseHeaders implements v2alpha.ResponseHeaderPolicy.
// PII masking operates on the body, so headers are passed through unchanged.
func (p *PIIMaskingRegexPolicy) OnResponseHeaders(ctx context.Context, respCtx *policy.ResponseHeaderContext, params map[string]interface{}) policy.ResponseHeaderAction {
	return policy.DownstreamResponseHeaderModifications{}
}

// OnRequestBody masks PII in the request body before forwarding to upstream.
func (p *PIIMaskingRegexPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	return p.processRequestBody(reqCtx, nil)
}

// processRequestBody masks PII in the request body before forwarding to upstream.
// Placeholders (e.g. [EMAIL_0000]) or redaction markers (*****) replace
// detected PII. Placeholder→original mappings are stored in shared metadata
// so processResponseBody can restore them.
func (p *PIIMaskingRegexPolicy) processRequestBody(reqCtx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	if len(p.params.PIIEntities) == 0 {
		return policy.UpstreamRequestModifications{}
	}

	if reqCtx.Body == nil || reqCtx.Body.Content == nil {
		return policy.UpstreamRequestModifications{}
	}
	payload := reqCtx.Body.Content

	extractedValue, ok, err := extractStringFromPath(payload, p.params.JsonPath)
	if err != nil {
		return p.buildErrorResponse(fmt.Sprintf("error extracting value from JSONPath: %v", err)).(policy.RequestAction)
	}
	if !ok {
		// Value at path is not a scalar (e.g. multimodal content array); skip masking.
		return policy.UpstreamRequestModifications{}
	}

	extractedValue = textCleanRegexCompiled.ReplaceAllString(extractedValue, "")
	extractedValue = strings.TrimSpace(extractedValue)

	var modifiedContent string
	if p.params.RedactPII {
		modifiedContent = p.redactPIIFromContent(extractedValue, p.params.PIIEntities)
	} else {
		if reqCtx.Metadata == nil {
			reqCtx.Metadata = make(map[string]interface{})
		}
		modifiedContent, err = p.maskPIIFromContent(extractedValue, p.params.PIIEntities, reqCtx.Metadata)
		if err != nil {
			return p.buildErrorResponse(fmt.Sprintf("error masking PII: %v", err)).(policy.RequestAction)
		}
	}

	if modifiedContent != "" && modifiedContent != extractedValue {
		modifiedPayload := p.updatePayloadWithMaskedContent(payload, extractedValue, modifiedContent, p.params.JsonPath)
		return policy.UpstreamRequestModifications{
			Body: modifiedPayload,
		}
	}

	return policy.UpstreamRequestModifications{}
}

// OnResponseBody restores PII placeholders in a buffered response body.
func (p *PIIMaskingRegexPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	return p.processResponseBody(respCtx, nil)
}

// processResponseBody restores PII placeholders in a buffered response body.
//
// Two body formats are handled:
//   - Plain JSON (non-streaming): choices[*].message.content
//   - SSE-buffered (chunked transfer of streaming response that this chain could not
//     process in streaming mode): multiple "data: {...}" lines, choices[*].delta.content.
//     The same restoreSSEChunk logic used by OnResponseBodyChunk is reused here.
func (p *PIIMaskingRegexPolicy) processResponseBody(respCtx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	if p.params.RedactPII {
		return policy.DownstreamResponseModifications{}
	}

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.DownstreamResponseModifications{}
	}

	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	if respCtx.ResponseBody == nil || respCtx.ResponseBody.Content == nil {
		return policy.DownstreamResponseModifications{}
	}

	bodyStr := string(respCtx.ResponseBody.Content)

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	if isSSEChunk(bodyStr) {
		// SSE-buffered: reuse the streaming restoration logic.
		action := p.restoreSSEChunk(bodyStr, restoreMap)
		if action.Body == nil {
			return policy.DownstreamResponseModifications{}
		}
		return policy.DownstreamResponseModifications{Body: action.Body}
	}

	// Plain JSON buffered response: try OpenAI choices[*].message.content first,
	// then fall back to raw placeholder replacement for generic JSON structures.
	updatedJSON, changed := restoreInChoices(bodyStr, restoreMap, "message")
	if changed {
		return policy.DownstreamResponseModifications{Body: []byte(updatedJSON)}
	}

	// Fallback: restore placeholders directly in the raw JSON bytes.
	action := p.restoreJSONChunk(bodyStr, restoreMap)
	if action.Body != nil {
		return policy.DownstreamResponseModifications{Body: action.Body}
	}
	return policy.DownstreamResponseModifications{}
}

// ─── Streaming restore (bounded-carry) ───────────────────────────────────────
//
// Restoration must survive a placeholder being split across chunk boundaries
// without buffering the whole response. The approach is streaming find/replace
// with a bounded holdback: every complete placeholder in the bytes seen so far
// is replaced and emitted immediately; the only bytes withheld are the shortest
// suffix that could still grow into a known placeholder ("[EMA" when
// "[EMAIL_0000]" is in this request's restore map). The carry is therefore
// bounded by the longest placeholder for the request (~tens of bytes), the
// response streams through with no added buffering, and the kernel's own
// accumulator limits are never bypassed.
//
// SSE responses need the same idea one level up: a placeholder can be split
// across the delta.content of several events, where the raw bytes never
// contain it contiguously. Content events are held only while the tail of
// their concatenated content is a prefix of a known placeholder, and resolved
// as soon as it completes, stops matching, or the stream ends ([DONE]/EOS).
//
// Per-request state lives in respCtx.Metadata under metadataKeyStreamState as a
// JSON *string*. It must not be stored as a Go struct pointer: the Python
// policy bridge serializes SharedContext.Metadata through structpb.NewStruct
// (pythonbridge/translator.go), which rejects arbitrary Go types
// ("proto: invalid type: *piimaskingregex.streamRestoreState") and would fail
// every chain containing a Python policy. Strings round-trip cleanly.
// The entry is deleted at end of stream so no response bytes outlive the request.

const (
	// metadataKeyStreamState holds the *streamRestoreState for this request.
	metadataKeyStreamState = "piimaskingregex:stream_state"

	// modeUnknown/modeRaw/modeSSE route chunks once per request. The decision is
	// sticky: an SSE stream never falls back to raw handling on a chunk that
	// happens not to contain a "data:" line (heartbeats, split frames).
	modeUnknown = 0
	modeRaw     = 1
	modeSSE     = 2

	// maxSSEPendingBytes is a defensive ceiling on the SSE hold buffer. The hold
	// condition (tail is a placeholder prefix) bounds it naturally — one event
	// per placeholder character in the worst case — so this only guards against
	// pathological streams. On overflow the pending events are restored
	// best-effort and emitted.
	maxSSEPendingBytes = 64 * 1024

	// SSE terminates an event with a blank line. Both line terminators are legal,
	// and a CRLF stream contains no "\n\n" at all, so both must be recognised.
	sseEventSeparator     = "\n\n"
	sseEventSeparatorCRLF = "\r\n\r\n"
)

// streamRestoreState is the per-request streaming state, persisted as a JSON
// string in respCtx.Metadata (see metadataKeyStreamState).
type streamRestoreState struct {
	Mode int `json:"m,omitempty"`

	// Carry holds tail bytes of the raw (non-SSE) body withheld because they are
	// a proper prefix of a known placeholder. Always shorter than the longest
	// placeholder for this request.
	Carry string `json:"c,omitempty"`

	// SSECarry holds a trailing incomplete SSE event (no "\n\n" yet).
	SSECarry string `json:"sc,omitempty"`
	// SSEPending holds complete SSE events withheld while their concatenated
	// delta.content tail could still grow into a placeholder.
	SSEPending string `json:"sp,omitempty"`
}

// loadStreamState reads the per-request state, tolerating a missing or
// unparseable entry by starting fresh.
func loadStreamState(metadata map[string]interface{}) *streamRestoreState {
	state := &streamRestoreState{}
	if raw, ok := metadata[metadataKeyStreamState].(string); ok && raw != "" {
		_ = json.Unmarshal([]byte(raw), state)
	}
	return state
}

// saveStreamState persists the state, removing the entry entirely when nothing
// is being withheld so the common case leaves no residue in metadata.
func saveStreamState(metadata map[string]interface{}, state *streamRestoreState) {
	if state.Carry == "" && state.SSECarry == "" && state.SSEPending == "" && state.Mode == modeUnknown {
		delete(metadata, metadataKeyStreamState)
		return
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		delete(metadata, metadataKeyStreamState)
		return
	}
	metadata[metadataKeyStreamState] = string(encoded)
}

// NeedsMoreResponseData implements v2alpha.StreamingResponsePolicy.
// Always false: cross-chunk state is handled inside OnResponseBodyChunk with a
// bounded carry, so the kernel should deliver every chunk immediately. This
// also keeps behaviour identical on the compressed path, where the kernel
// never consults this method.
func (p *PIIMaskingRegexPolicy) NeedsMoreResponseData(accumulated []byte) bool {
	return false
}

// OnResponseBodyChunk implements v2alpha.StreamingResponsePolicy.
// Restores masked PII in response chunks.
//
// LLMs always use Transfer-Encoding: chunked, so this method handles two formats:
//   - SSE streaming: lines prefixed with "data: ", restores in choices[*].delta.content
//   - Full JSON (non-streaming, chunked transfer): restores in raw JSON bytes
func (p *PIIMaskingRegexPolicy) OnResponseBodyChunk(ctx context.Context, respCtx *policy.ResponseStreamContext, chunk *policy.StreamBody, params map[string]interface{}) policy.StreamingResponseAction {
	if p.params.RedactPII {
		return policy.ForwardResponseChunk{}
	}
	if chunk == nil {
		return policy.ForwardResponseChunk{}
	}
	// Note: an empty chunk is NOT an early return — an empty EndOfStream
	// sentinel must still flush any withheld carry below.

	maskedPII, exists := respCtx.Metadata[MetadataKeyPIIEntities]
	if !exists {
		return policy.ForwardResponseChunk{}
	}
	maskedPIIMap, ok := maskedPII.(map[string]string)
	if !ok || len(maskedPIIMap) == 0 {
		return policy.ForwardResponseChunk{}
	}

	// maskedPIIMap is keyed original→placeholder (set by maskPIIFromContent).
	// The restore helpers expect placeholder→original, so invert before use.
	restoreMap := invertStringMap(maskedPIIMap)

	// respCtx.Metadata is non-nil here: the MetadataKeyPIIEntities lookup above
	// already returned on a missing entry, which a nil map cannot have.
	state := loadStreamState(respCtx.Metadata)

	chunkStr := string(chunk.Chunk)
	state.detectMode(respCtx, chunkStr)

	var out string
	if state.Mode == modeSSE {
		out = p.restoreSSEStream(state, chunkStr, chunk.EndOfStream, restoreMap)
	} else {
		out = p.restoreRawStream(state, chunkStr, chunk.EndOfStream, restoreMap)
	}

	if chunk.EndOfStream {
		// Nothing may outlive the stream: any residual carry has been emitted above.
		delete(respCtx.Metadata, metadataKeyStreamState)
	} else {
		saveStreamState(respCtx.Metadata, state)
	}

	if out == chunkStr {
		return policy.ForwardResponseChunk{} // passthrough, nothing withheld or changed
	}
	// Body must be non-nil even when out is "" (every byte of this chunk is being
	// withheld): the executor forwards the original chunk unchanged when Body is
	// nil, which would emit the withheld bytes here and again when they are
	// released. append guarantees a non-nil slice; []byte("") does not.
	return policy.ForwardResponseChunk{Body: append([]byte{}, out...)}
}

// detectMode fixes the SSE-vs-raw routing decision for the request. The
// upstream Content-Type is authoritative when present; the first chunk's shape
// is the fallback for contexts without response headers. An SSE comment line
// (": keep-alive") counts as SSE — it can legitimately arrive before the first
// data event and must not push the stream onto the raw path.
func (s *streamRestoreState) detectMode(respCtx *policy.ResponseStreamContext, chunkStr string) {
	if s.Mode != modeUnknown {
		return
	}
	if respCtx.ResponseHeaders != nil {
		if ct := respCtx.ResponseHeaders.Get("content-type"); len(ct) > 0 {
			if strings.HasPrefix(strings.ToLower(ct[0]), "text/event-stream") {
				s.Mode = modeSSE
			} else {
				s.Mode = modeRaw
			}
			return
		}
	}
	trimmed := strings.TrimLeft(chunkStr, "\r\n ")
	if strings.HasPrefix(trimmed, ":") || isSSEChunk(chunkStr) {
		s.Mode = modeSSE
		return
	}
	if trimmed != "" {
		s.Mode = modeRaw
	}
}

// restoreRawStream is the non-SSE path: streaming find/replace with a bounded
// placeholder-prefix carry. Output preserves every byte of the body except
// that complete placeholders are replaced with their JSON-escaped originals.
func (p *PIIMaskingRegexPolicy) restoreRawStream(state *streamRestoreState, chunkStr string, endOfStream bool, restoreMap map[string]string) string {
	buf := state.Carry + chunkStr
	state.Carry = ""

	result := restoreJSONBytes(buf, restoreMap)

	if !endOfStream {
		if hold := placeholderPrefixSuffixLen(result, restoreMap); hold > 0 {
			state.Carry = result[len(result)-hold:]
			result = result[:len(result)-hold]
		}
	}
	return result
}

// restoreSSEStream is the SSE path. Complete events flow through immediately
// unless their concatenated delta.content ends in a placeholder prefix, in
// which case they are withheld until the placeholder completes, stops
// matching, or the stream terminates ([DONE]/EOS).
func (p *PIIMaskingRegexPolicy) restoreSSEStream(state *streamRestoreState, chunkStr string, endOfStream bool, restoreMap map[string]string) string {
	buf := state.SSECarry + chunkStr
	state.SSECarry = ""

	// Split off a trailing incomplete event (no terminating blank line yet).
	complete := buf
	if !endOfStream {
		if end := lastCompleteEventEnd(buf); end >= 0 {
			complete = buf[:end]
			state.SSECarry = buf[end:]
		} else {
			state.SSECarry = buf
			complete = ""
		}
	}

	pending := state.SSEPending + complete
	state.SSEPending = ""
	if pending == "" {
		return ""
	}

	// Terminal conditions force resolution: nothing further can complete a
	// pending placeholder.
	terminal := endOfStream || sseFrameHasDone(complete)

	assembled := concatDeltaContent(pending, DefaultStreamingJSONPaths)
	if assembled == "" {
		return pending // no content events (heartbeats, usage frames, [DONE])
	}

	restored := restore(assembled, restoreMap)
	if !terminal && len(pending) <= maxSSEPendingBytes {
		if hold := placeholderPrefixSuffixLen(restored, restoreMap); hold > 0 {
			// Tail could still grow into a placeholder — withhold these events.
			state.SSEPending = pending
			return ""
		}
	}

	if restored == assembled {
		return pending // nothing to rewrite — emit events exactly as received
	}
	return mergeSSEContent(pending, restored, DefaultStreamingJSONPaths)
}

// lastCompleteEventEnd returns the offset just past the last event terminator in
// buf, or -1 when buf holds no complete event. Both LF and CRLF terminators are
// recognised: a CRLF stream contains no "\n\n" at all, so matching LF alone
// would hold every event in SSECarry until end-of-stream — an unbounded buffer
// and no tokens reaching the client until the stream finishes.
func lastCompleteEventEnd(buf string) int {
	end := -1
	if i := strings.LastIndex(buf, sseEventSeparator); i >= 0 {
		end = i + len(sseEventSeparator)
	}
	if i := strings.LastIndex(buf, sseEventSeparatorCRLF); i >= 0 && i+len(sseEventSeparatorCRLF) > end {
		end = i + len(sseEventSeparatorCRLF)
	}
	return end
}

// sseLineBody drops the trailing CR left on every line when a CRLF-delimited
// frame is split on "\n", so field parsing is terminator-agnostic.
func sseLineBody(line string) string {
	return strings.TrimSuffix(line, "\r")
}

// sseDataPayload returns the payload of an SSE "data: " field line and whether
// line is one at all. CR-tolerant, so "data: [DONE]\r" yields "[DONE]".
func sseDataPayload(line string) (string, bool) {
	body := sseLineBody(line)
	if !strings.HasPrefix(body, sseDataPrefix) {
		return "", false
	}
	return strings.TrimPrefix(body, sseDataPrefix), true
}

// rebuildSSEDataLine reassembles a data line around a rewritten payload,
// preserving the line's original CR terminator.
func rebuildSSEDataLine(line, payload string) string {
	if strings.HasSuffix(line, "\r") {
		return sseDataPrefix + payload + "\r"
	}
	return sseDataPrefix + payload
}

// sseFrameHasDone reports whether raw carries a data field whose payload is
// exactly [DONE]. A substring search over the whole frame would instead fire on
// assistant text that merely mentions "data: [DONE]", treating it as end of
// stream and releasing a half-buffered placeholder as a visible leak.
func sseFrameHasDone(raw string) bool {
	for _, line := range strings.Split(raw, "\n") {
		if payload, ok := sseDataPayload(line); ok && payload == sseDone {
			return true
		}
	}
	return false
}

// concatDeltaContent concatenates the delta.content of every data event in raw
// SSE text, in order.
func concatDeltaContent(raw string, paths []string) string {
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		sb.WriteString(extractFirstDeltaContent(jsonStr, paths))
	}
	return sb.String()
}

// isSSEFieldLine reports whether line is an SSE field that belongs to the event
// block it precedes. Comments (": keep-alive") are deliberately excluded: they
// are valid standalone and are preserved wherever they appear.
func isSSEFieldLine(line string) bool {
	body := sseLineBody(line)
	return strings.HasPrefix(body, sseEventPrefix) ||
		strings.HasPrefix(body, "id:") ||
		strings.HasPrefix(body, "retry:")
}

// markEventBlockForRemoval marks the whole SSE block owning the data line at
// dataIdx: the field lines immediately preceding it and the blank separator
// terminating it. Dropping only the data line would leave its "event:" line
// orphaned — a block with no data — which is malformed for providers that emit
// a field line per event, Anthropic being the one that does.
func markEventBlockForRemoval(lines []string, dataIdx int, removeLines map[int]bool) {
	removeLines[dataIdx] = true
	// Walk back over this block's field lines. A blank line, a comment, or the
	// preceding event's data line all stop the walk, so no other block is touched.
	for j := dataIdx - 1; j >= 0 && isSSEFieldLine(lines[j]); j-- {
		removeLines[j] = true
	}
	if dataIdx+1 < len(lines) && sseLineBody(lines[dataIdx+1]) == "" {
		removeLines[dataIdx+1] = true
	}
}

// mergeSSEContent writes restoredContent into the first content-bearing event
// of raw and drops the other content events (their content has been merged),
// keeping every non-content line — comments, [DONE], usage frames — in order.
func mergeSSEContent(raw, restoredContent string, paths []string) string {
	lines := strings.Split(raw, "\n")
	first := -1
	removeLines := make(map[int]bool)
	for i, line := range lines {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		content := extractFirstDeltaContent(jsonStr, paths)
		if content == "" {
			continue
		}
		if first == -1 {
			first = i
			lines[i] = replaceContentInSSELine(line, content, restoredContent, paths)
			continue
		}
		markEventBlockForRemoval(lines, i, removeLines)
	}
	if first == -1 {
		return raw
	}
	filtered := lines[:0:0]
	for i, line := range lines {
		if removeLines[i] {
			continue
		}
		filtered = append(filtered, line)
	}
	return strings.Join(filtered, "\n")
}

// placeholderPrefixSuffixLen returns the length of the longest suffix of s
// that is a proper prefix of any placeholder in restoreMap (keys), or 0.
func placeholderPrefixSuffixLen(s string, restoreMap map[string]string) int {
	longest := 0
	for placeholder := range restoreMap {
		max := len(placeholder) - 1
		if max > len(s) {
			max = len(s)
		}
		for l := max; l > longest; l-- {
			if strings.HasSuffix(s, placeholder[:l]) {
				longest = l
				break
			}
		}
	}
	return longest
}

// restoreJSONBytes replaces every complete placeholder in s with its
// JSON-escaped original, preserving all other bytes exactly.
func restoreJSONBytes(s string, restoreMap map[string]string) string {
	result := s
	for placeholder, original := range restoreMap {
		if !strings.Contains(result, placeholder) {
			continue
		}
		encodedBytes, err := json.Marshal(original)
		if err != nil {
			continue
		}
		escapedOriginal := string(encodedBytes[1 : len(encodedBytes)-1])
		result = strings.ReplaceAll(result, placeholder, escapedOriginal)
	}
	return result
}

// ─── SSE / Streaming helpers ─────────────────────────────────────────────────

// isSSEChunk reports whether the chunk looks like SSE data (has at least one "data: " or "event:" line).
func isSSEChunk(s string) bool {
	for _, line := range strings.SplitN(s, "\n", 5) {
		if strings.HasPrefix(line, sseDataPrefix) || strings.HasPrefix(line, sseEventPrefix) {
			return true
		}
	}
	return false
}

// restoreSSEChunk handles SSE streaming format: "data: {...}\n\n" lines.
//
// When the accumulator flushes a batch of SSE events (e.g. the placeholder
// [EMAIL_0000] split across " [", "EMAIL", "_", "0000", "]" in separate events),
// no single event contains the full placeholder. We therefore concatenate all
// delta.content values, restore on the full string, then redistribute: the
// first content-bearing event gets the complete restored text, and all subsequent
// events whose content has been merged into the first are dropped entirely.
func (p *PIIMaskingRegexPolicy) restoreSSEChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	lines := strings.Split(chunkStr, "\n")

	// Collect every SSE data line that carries a non-empty delta.content.
	type contentLine struct {
		lineIdx int
		content string
	}
	var contentLines []contentLine
	for i, line := range lines {
		jsonStr, ok := sseDataPayload(line)
		if !ok || jsonStr == sseDone {
			continue
		}
		if c := extractFirstDeltaContent(jsonStr, DefaultStreamingJSONPaths); c != "" {
			contentLines = append(contentLines, contentLine{lineIdx: i, content: c})
		}
	}

	if len(contentLines) == 0 {
		return policy.ForwardResponseChunk{}
	}

	// Concatenate fragments and restore in one pass.
	var sb strings.Builder
	for _, cl := range contentLines {
		sb.WriteString(cl.content)
	}
	fullContent := sb.String()
	restoredContent := restore(fullContent, maskedMap)

	if restoredContent == fullContent {
		return policy.ForwardResponseChunk{}
	}

	// Redistribute: first content-bearing event gets the full restored text;
	// subsequent events are dropped entirely.
	lines[contentLines[0].lineIdx] = replaceContentInSSELine(
		lines[contentLines[0].lineIdx], contentLines[0].content, restoredContent,
		DefaultStreamingJSONPaths,
	)
	removeLines := make(map[int]bool, len(contentLines)-1)
	for _, cl := range contentLines[1:] {
		markEventBlockForRemoval(lines, cl.lineIdx, removeLines)
	}

	filtered := lines[:0:0]
	for i, line := range lines {
		if removeLines[i] {
			continue
		}
		filtered = append(filtered, line)
	}

	return policy.ForwardResponseChunk{Body: []byte(strings.Join(filtered, "\n"))}
}

// extractFirstDeltaContent parses a single SSE JSON line and returns the
// delta.content value from the first choice, or empty string if absent/empty.
func extractFirstDeltaContent(jsonStr string, paths []string) string {
	content, _ := extractFirstDeltaContentKeyed(jsonStr, paths)
	return content
}

// extractFirstDeltaContentKeyed returns the assistant text carried by one SSE
// data payload along with the JSONPath it was found at, so an in-place rewrite
// can target that same field. Paths are tried in order; the first that yields a
// non-empty string wins.
func extractFirstDeltaContentKeyed(jsonStr string, paths []string) (string, string) {
	for _, path := range paths {
		text, err := utils.ExtractStringValueFromJsonpath([]byte(jsonStr), path)
		if err == nil && text != "" {
			return text, path
		}
	}
	return "", ""
}

// jsonPathLeafKey returns the final field name of a JSONPath, e.g. "content"
// for "$.choices[0].delta.content". Used to locate the value in the raw JSON so
// a rewrite can preserve the frame's original key order and spacing instead of
// re-marshaling it.
func jsonPathLeafKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return ""
}

// replaceContentInSSELine replaces the delta.content value in a "data: {...}" SSE
// line in-place, touching only the JSON-encoded content value and leaving all
// other fields intact. Falls back to a full re-marshal if the in-place
// replacement cannot locate the expected token.
func replaceContentInSSELine(line, oldContent, newContent string, paths []string) string {
	jsonStr, ok := sseDataPayload(line)
	if !ok {
		return line
	}
	_, matchedPath := extractFirstDeltaContentKeyed(jsonStr, paths)
	if matchedPath == "" {
		return line
	}
	key := jsonPathLeafKey(matchedPath)
	oldJSON, err1 := json.Marshal(oldContent)
	newJSON, err2 := json.Marshal(newContent)
	if err1 != nil || err2 != nil {
		return updateDeltaContentInLine(line, newContent, matchedPath)
	}
	updated := strings.Replace(jsonStr, `"`+key+`":`+string(oldJSON), `"`+key+`":`+string(newJSON), 1)
	if updated == jsonStr {
		// Token not found (e.g. whitespace around colon) — fall back.
		return updateDeltaContentInLine(line, newContent, matchedPath)
	}
	return rebuildSSEDataLine(line, updated)
}

// updateDeltaContentInLine is the fallback full-remarshal path used when
// replaceContentInSSELine cannot locate the content token in the raw JSON.
// It writes through the same JSONPath the text was extracted from, so it stays
// correct for any provider shape without knowing which one this is.
func updateDeltaContentInLine(line, newContent, matchedPath string) string {
	jsonStr, ok := sseDataPayload(line)
	if !ok {
		return line
	}
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return line
	}
	if err := utils.SetValueAtJSONPath(data, matchedPath, newContent); err != nil {
		return line
	}
	b, err := json.Marshal(data)
	if err != nil {
		return line
	}
	return rebuildSSEDataLine(line, string(b))
}

// restoreJSONChunk handles full JSON responses delivered via chunked transfer encoding.
// Placeholders are replaced directly in the raw JSON bytes so that key order,
// whitespace, and any trailing newline from the LLM are preserved exactly.
func (p *PIIMaskingRegexPolicy) restoreJSONChunk(chunkStr string, maskedMap map[string]string) policy.ForwardResponseChunk {
	result := restoreJSONBytes(chunkStr, maskedMap)
	if result == chunkStr {
		return policy.ForwardResponseChunk{}
	}
	return policy.ForwardResponseChunk{Body: []byte(result)}
}

// restoreInChoices parses a JSON string, restores PII placeholders in
// choices[*].<choiceKey>.content, and returns the updated JSON.
// choiceKey is "message" for non-streaming or "delta" for streaming.
func restoreInChoices(jsonStr string, maskedMap map[string]string, choiceKey string) (string, bool) {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return jsonStr, false
	}

	choicesRaw, ok := data["choices"]
	if !ok {
		return jsonStr, false
	}
	choices, ok := choicesRaw.([]interface{})
	if !ok || len(choices) == 0 {
		return jsonStr, false
	}

	modified := false
	for _, choiceRaw := range choices {
		choice, ok := choiceRaw.(map[string]interface{})
		if !ok {
			continue
		}
		subRaw, ok := choice[choiceKey]
		if !ok {
			continue
		}
		sub, ok := subRaw.(map[string]interface{})
		if !ok {
			continue
		}
		content, ok := sub["content"].(string)
		if !ok || content == "" {
			continue
		}
		restored := restore(content, maskedMap)
		if restored != content {
			sub["content"] = restored
			modified = true
		}
	}

	if !modified {
		return jsonStr, false
	}

	updatedBytes, err := json.Marshal(data)
	if err != nil {
		return jsonStr, false
	}
	return string(updatedBytes), true
}

// invertStringMap returns a new map with keys and values swapped.
func invertStringMap(m map[string]string) map[string]string {
	inv := make(map[string]string, len(m))
	for k, v := range m {
		inv[v] = k
	}
	return inv
}

// restore replaces placeholders with their original values.
// maskedMap is placeholder → original.
func restore(content string, maskedMap map[string]string) string {
	result := content
	for placeholder, original := range maskedMap {
		result = strings.ReplaceAll(result, placeholder, original)
	}
	return result
}

// extractStringFromPath extracts the value at jsonPath from payload as a string.
// Returns (value, true, nil) when the value is a scalar string or number.
// Returns ("", false, nil) when the value exists but is not a scalar (e.g. array/object).
// Returns ("", false, err) on path or parse errors.
func extractStringFromPath(payload []byte, jsonPath string) (string, bool, error) {
	if jsonPath == "" {
		return string(payload), true, nil
	}
	var jsonData map[string]interface{}
	if err := json.Unmarshal(payload, &jsonData); err != nil {
		return "", false, err
	}
	raw, err := utils.ExtractValueFromJsonpath(jsonData, jsonPath)
	if err != nil {
		return "", false, err
	}
	switch v := raw.(type) {
	case string:
		return v, true, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true, nil
	case int:
		return strconv.Itoa(v), true, nil
	default:
		return "", false, nil
	}
}

func (p *PIIMaskingRegexPolicy) buildErrorResponse(reason string) interface{} {
	responseBody := map[string]interface{}{
		"code":    APIMInternalExceptionCode,
		"message": "Error occurred during pii-masking-regex mediation: " + reason,
	}

	bodyBytes, err := json.Marshal(responseBody)
	if err != nil {
		bodyBytes = []byte(fmt.Sprintf(`{"code":%d,"type":"PII_MASKING_REGEX","message":"Internal error"}`, APIMInternalExceptionCode))
	}

	// For PII masking, errors typically occur in request phase, but return as ImmediateResponse
	return policy.ImmediateResponse{
		StatusCode: APIMInternalErrorCode,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: bodyBytes,
	}
}
