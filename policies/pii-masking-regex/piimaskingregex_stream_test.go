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
	"strings"
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// ─── harness ─────────────────────────────────────────────────────────────────

// driveResponseStream feeds chunks to OnResponseBodyChunk exactly as the kernel
// does (EndOfStream on the last) and reconstructs the bytes sent downstream
// using the SDK action semantics: ForwardResponseChunk.Body nil = forward the
// original chunk unchanged, non-nil = replace it (empty slice = emit nothing).
func driveResponseStream(t *testing.T, p *PIIMaskingRegexPolicy, respCtx *policy.ResponseStreamContext, chunks []string) string {
	t.Helper()
	var out strings.Builder
	for i, c := range chunks {
		sb := &policy.StreamBody{
			Chunk:       []byte(c),
			EndOfStream: i == len(chunks)-1,
			Index:       uint64(i),
		}
		action := p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)
		fwd, ok := action.(policy.ForwardResponseChunk)
		if !ok {
			t.Fatalf("chunk %d: expected ForwardResponseChunk, got %T", i, action)
		}
		if fwd.Body == nil {
			out.WriteString(c)
		} else {
			out.Write(fwd.Body)
		}
	}
	return out.String()
}

func streamingRespCtx(contentType string, mapping map[string]string) *policy.ResponseStreamContext {
	metadata := map[string]interface{}{}
	if mapping != nil {
		metadata[MetadataKeyPIIEntities] = mapping
	}
	ctx := &policy.ResponseStreamContext{
		SharedContext: &policy.SharedContext{RequestID: "req-id", Metadata: metadata},
	}
	if contentType != "" {
		ctx.ResponseHeaders = policy.NewHeaders(map[string][]string{"content-type": {contentType}})
	}
	return ctx
}

// splitEvery breaks s into chunks of at most n bytes, mimicking arbitrary
// chunked-transfer framing boundaries.
func splitEvery(s string, n int) []string {
	var chunks []string
	for len(s) > n {
		chunks = append(chunks, s[:n])
		s = s[n:]
	}
	if len(s) > 0 {
		chunks = append(chunks, s)
	}
	return chunks
}

func sseEvent(content string) string {
	ev, _ := json.Marshal(map[string]any{
		"id":      "chatcmpl-sse",
		"object":  "chat.completion.chunk",
		"choices": []any{map[string]any{"index": 0, "delta": map[string]any{"content": content}}},
	})
	return "data: " + string(ev) + "\n\n"
}

// assembleSSEContent concatenates delta.content across every data event.
func assembleSSEContent(t *testing.T, raw string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			continue
		}
		sb.WriteString(extractFirstDeltaContent(payload, DefaultStreamingJSONPaths))
	}
	return sb.String()
}

const maskedJSONBody = `{
  "id": "chatcmpl-ECLSc2xRestoreTest",
  "object": "chat.completion",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "Confirmation sent to [EMAIL_0000]. Call [PHONE_0001] if anything changes."
      },
      "finish_reason": "stop"
    }
  ]
}
`

// ─── non-SSE (plain JSON over chunked transfer) ──────────────────────────────

// The core regression: the body arrives in small chunks that split placeholders
// across boundaries. Every byte must survive and every placeholder must be
// restored, at any chunk size.
func TestNonSSE_RestoresAcrossEveryChunkBoundary(t *testing.T) {
	want := strings.NewReplacer(
		"[EMAIL_0000]", "guest@example.com",
		"[PHONE_0001]", "212-555-0175",
	).Replace(maskedJSONBody)

	for _, size := range []int{1, 2, 3, 5, 7, 11, 27, 64, 4096} {
		p := mustGetPIIPolicy(t, map[string]interface{}{"email": true, "phone": true})
		respCtx := streamingRespCtx("application/json", map[string]string{
			"guest@example.com": "[EMAIL_0000]",
			"212-555-0175":      "[PHONE_0001]",
		})
		got := driveResponseStream(t, p, respCtx, splitEvery(maskedJSONBody, size))
		if got != want {
			t.Errorf("chunk size %d: body mismatch\n got: %q\nwant: %q", size, got, want)
		}
	}
}

// A response with no placeholder in it must be forwarded byte-for-byte.
func TestNonSSE_NoPlaceholderIsForwardedIntact(t *testing.T) {
	body := `{"id":"chatcmpl-x","choices":[{"message":{"content":"How can I help you today?"}}]}` + "\n"
	for _, size := range []int{1, 7, 27, 4096} {
		p := mustGetPIIPolicy(t, map[string]interface{}{"phone": true})
		respCtx := streamingRespCtx("application/json", map[string]string{"212-555-0175": "[PHONE_0000]"})
		if got := driveResponseStream(t, p, respCtx, splitEvery(body, size)); got != body {
			t.Errorf("chunk size %d: body altered\n got: %q\nwant: %q", size, got, body)
		}
	}
}

// A separate empty EndOfStream sentinel must flush any withheld carry.
func TestNonSSE_EmptyEndOfStreamSentinelFlushesCarry(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	chunks := append(splitEvery(maskedJSONBody, 9), "")
	got := driveResponseStream(t, p, respCtx, chunks)
	want := strings.Replace(maskedJSONBody, "[EMAIL_0000]", "guest@example.com", 1)
	if got != want {
		t.Fatalf("sentinel flush mismatch\n got: %q\nwant: %q", got, want)
	}
}

// A body whose tail genuinely looks like the start of a placeholder must not be
// swallowed — the carry has to be released at end of stream.
func TestNonSSE_TrailingPlaceholderPrefixIsNotSwallowed(t *testing.T) {
	body := `{"content":"an unclosed bracket [EMA`
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})
	if got := driveResponseStream(t, p, respCtx, splitEvery(body, 4)); got != body {
		t.Fatalf("trailing prefix lost\n got: %q\nwant: %q", got, body)
	}
}

// The carry must stay bounded by the longest placeholder — the policy must
// never buffer the whole body (that would bypass the kernel's accumulator cap).
func TestNonSSE_CarryStaysBounded(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	payload := strings.Repeat("a", 8192)
	maxHeld := 0
	for i := 0; i < 64; i++ {
		sb := &policy.StreamBody{Chunk: []byte(payload), EndOfStream: false, Index: uint64(i)}
		p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)
		if raw, ok := respCtx.Metadata[metadataKeyStreamState].(string); ok && len(raw) > maxHeld {
			maxHeld = len(raw)
		}
	}
	if maxHeld > 1024 {
		t.Fatalf("policy withheld %d bytes of state; expected a small bounded carry", maxHeld)
	}
}

// ─── SSE ─────────────────────────────────────────────────────────────────────

// A placeholder split across delta events must be restored, however finely the
// upstream tokenises it — including far beyond the old 5-data-line lookahead.
func TestSSE_RestoresPlaceholderSplitAcrossEvents(t *testing.T) {
	fragments := [][]string{
		{"send ", "it ", "to ", "[EMAIL_0000]", " please"},
		{"send ", "it ", "to ", "[", "EMAIL", "_", "0000", "]", " please"},
		{"send ", "it ", "to ", "[", "E", "M", "A", "I", "L", "_", "0", "0", "0", "0", "]", " please"},
	}
	for i, frags := range fragments {
		p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
		respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

		var stream strings.Builder
		for _, f := range frags {
			stream.WriteString(sseEvent(f))
		}
		stream.WriteString("data: [DONE]\n\n")

		out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), 40))
		got := assembleSSEContent(t, out)
		const want = "send it to guest@example.com please"
		if got != want {
			t.Errorf("case %d: assembled content mismatch\n got: %q\nwant: %q", i, got, want)
		}
		if strings.Contains(out, "[EMAIL_0000]") {
			t.Errorf("case %d: placeholder leaked to client:\n%s", i, out)
		}
		if !strings.Contains(out, "data: [DONE]") {
			t.Errorf("case %d: [DONE] terminator missing:\n%s", i, out)
		}
	}
}

// A leading SSE comment/heartbeat must be forwarded in place, before the first
// data event — never reordered to the end of the stream.
func TestSSE_LeadingHeartbeatKeepsItsPosition(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	chunks := []string{
		": keep-alive\n\n",
		sseEvent("hello "),
		sseEvent("[EMAIL_0000]"),
		"data: [DONE]\n\n",
	}
	out := driveResponseStream(t, p, respCtx, chunks)

	if !strings.Contains(out, ": keep-alive") {
		t.Fatalf("heartbeat dropped:\n%s", out)
	}
	hb := strings.Index(out, ": keep-alive")
	firstData := strings.Index(out, "data: ")
	done := strings.Index(out, "data: [DONE]")
	if hb > firstData {
		t.Errorf("heartbeat reordered after the first data event:\n%s", out)
	}
	if hb > done {
		t.Errorf("heartbeat emitted after [DONE]:\n%s", out)
	}
	if got := assembleSSEContent(t, out); got != "hello guest@example.com" {
		t.Errorf("content mismatch: got %q", got)
	}
}

// Ordinary prose containing '[' must not stall the stream: with no placeholder
// prefix matching, every event flows straight through.
func TestSSE_BracketInProseDoesNotWithhold(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	chunk := sseEvent("see [1] and [2] for details")
	sb := &policy.StreamBody{Chunk: []byte(chunk), EndOfStream: false}
	action := p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)
	fwd := action.(policy.ForwardResponseChunk)
	if fwd.Body != nil && len(fwd.Body) == 0 {
		t.Fatal("event was withheld despite containing no placeholder prefix")
	}
}

// An SSE stream must stay on the SSE path even when a chunk carries no data
// line at all, and content must not be corrupted by mid-frame chunk splits.
func TestSSE_SurvivesArbitraryChunkSplits(t *testing.T) {
	var stream strings.Builder
	stream.WriteString(": keep-alive\n\n")
	for _, f := range []string{"call ", "[", "PHONE", "_", "0000", "]", " now"} {
		stream.WriteString(sseEvent(f))
	}
	stream.WriteString("data: [DONE]\n\n")

	for _, size := range []int{1, 3, 17, 64, 4096} {
		p := mustGetPIIPolicy(t, map[string]interface{}{"phone": true})
		respCtx := streamingRespCtx("text/event-stream", map[string]string{"212-555-0175": "[PHONE_0000]"})
		out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), size))
		if got := assembleSSEContent(t, out); got != "call 212-555-0175 now" {
			t.Errorf("chunk size %d: content mismatch: got %q", size, got)
		}
		if strings.Contains(out, "[PHONE_0000]") {
			t.Errorf("chunk size %d: placeholder leaked:\n%s", size, out)
		}
	}
}

// ─── contract guards ─────────────────────────────────────────────────────────

// The kernel must hand us every chunk directly; cross-chunk state is ours.
func TestNeedsMoreResponseData_AlwaysFalse(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	for _, in := range []string{"", "{", `{"a":"b"}`, "data: {\"choices\":[]}\n\n", "[EMA"} {
		if p.NeedsMoreResponseData([]byte(in)) {
			t.Errorf("NeedsMoreResponseData(%q) = true, want false", in)
		}
	}
}

// Requests that masked nothing must stream through untouched.
func TestNoMetadata_StreamsThroughUnchanged(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", nil)
	if got := driveResponseStream(t, p, respCtx, splitEvery(maskedJSONBody, 33)); got != maskedJSONBody {
		t.Fatalf("body altered when no PII was masked:\n%s", got)
	}
}

// Per-request state must be a JSON-safe scalar. The Python policy bridge
// converts SharedContext.Metadata via structpb.NewStruct on every call, which
// rejects arbitrary Go types ("proto: invalid type: *piimaskingregex...") and
// would break any chain containing a Python policy. Regression guard against
// storing a struct pointer (or any non-scalar) in metadata.
func TestStreamState_IsJSONSafeScalar(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	// Mid-stream chunk ending in a placeholder prefix — forces state to be stored.
	sb := &policy.StreamBody{Chunk: []byte(`{"content":"mail [EMA`), EndOfStream: false}
	p.OnResponseBodyChunk(context.Background(), respCtx, sb, nil)

	raw, ok := respCtx.Metadata[metadataKeyStreamState]
	if !ok {
		t.Fatal("expected stream state to be stored mid-stream")
	}
	encoded, isString := raw.(string)
	if !isString {
		t.Fatalf("stream state must be stored as a string (structpb-safe), got %T", raw)
	}
	if !json.Valid([]byte(encoded)) {
		t.Fatalf("stream state is not valid JSON: %q", encoded)
	}
}

// State must not outlive the stream: nothing is left in metadata once the
// response has completed.
func TestStreamState_ClearedAtEndOfStream(t *testing.T) {
	p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
	respCtx := streamingRespCtx("application/json", map[string]string{"guest@example.com": "[EMAIL_0000]"})

	driveResponseStream(t, p, respCtx, splitEvery(maskedJSONBody, 9))
	if _, ok := respCtx.Metadata[metadataKeyStreamState]; ok {
		t.Fatal("stream state still present after end of stream")
	}
}

// ─── Anthropic SSE wire format ───────────────────────────────────────────────

// anthropicDeltaEvent builds an Anthropic content_block_delta frame, whose
// assistant text lives at delta.text rather than choices[].delta.content.
func anthropicDeltaEvent(text string) string {
	ev, _ := json.Marshal(map[string]any{
		"type":  "content_block_delta",
		"index": 0,
		"delta": map[string]any{"type": "text_delta", "text": text},
	})
	return "event: content_block_delta\ndata: " + string(ev) + "\n\n"
}

// assembleAnthropicContent concatenates delta.text across every data event.
func assembleAnthropicContent(t *testing.T, raw string) string {
	t.Helper()
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		var data map[string]any
		if json.Unmarshal([]byte(payload), &data) != nil {
			continue
		}
		delta, _ := data["delta"].(map[string]any)
		text, _ := delta["text"].(string)
		sb.WriteString(text)
	}
	return sb.String()
}

// Anthropic streams carry assistant text as delta.text on content_block_delta,
// with no "choices" array at all. Extraction that only understood the OpenAI
// shape found no content, so nothing was ever restored and the placeholder was
// delivered to the client — on every encoding, compression irrelevant. Found by
// running the mock Anthropic backend through the real gateway.
func TestSSE_AnthropicFormatRestoresAcrossEvents(t *testing.T) {
	fragments := [][]string{
		{"send ", "it ", "to ", "[EMAIL_0000]", " please"},
		{"send ", "it ", "to ", "[", "EMAIL", "_", "0000", "]", " please"},
		{"send ", "it ", "to ", "[", "E", "M", "A", "I", "L", "_", "0", "0", "0", "0", "]", " please"},
	}
	for i, frags := range fragments {
		p := mustGetPIIPolicy(t, map[string]interface{}{"email": true})
		respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

		var stream strings.Builder
		stream.WriteString("event: message_start\ndata: {\"type\":\"message_start\"}\n\n")
		stream.WriteString(": heartbeat\n\n")
		for _, f := range frags {
			stream.WriteString(anthropicDeltaEvent(f))
		}
		stream.WriteString("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")

		out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), 40))

		if got, want := assembleAnthropicContent(t, out), "send it to guest@example.com please"; got != want {
			t.Errorf("case %d: assembled content mismatch\n got: %q\nwant: %q", i, got, want)
		}
		if strings.Contains(out, "[EMAIL_0000]") {
			t.Errorf("case %d: placeholder leaked to client:\n%s", i, out)
		}
		if !strings.Contains(out, "message_stop") {
			t.Errorf("case %d: terminal event missing:\n%s", i, out)
		}
	}
}

// Gemini's streaming shape is covered by the defaults, and a provider that no
// default covers is supported by configuration alone. Together these are the
// claim that this policy is not bound to one vendor's wire format.
func TestSSE_ProviderShapesAreDataDriven(t *testing.T) {
	cases := []struct {
		name     string
		params   map[string]interface{}
		event    func(text string) string
		assemble func(raw string) string
	}{
		{
			name:   "gemini-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"candidates": []any{map[string]any{
						"content": map[string]any{"parts": []any{map[string]any{"text": text}}},
					}},
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					cands, _ := d["candidates"].([]any)
					for _, c := range cands {
						cm, _ := c.(map[string]any)
						content, _ := cm["content"].(map[string]any)
						parts, _ := content["parts"].([]any)
						for _, pt := range parts {
							pm, _ := pt.(map[string]any)
							s, _ := pm["text"].(string)
							sb.WriteString(s)
						}
					}
				}
				return sb.String()
			},
		},
		{
			// OpenAI Responses API: the text is a plain string at the top-level
			// "delta" key, matched by the trailing "$.delta" fallback.
			name:   "openai-responses-api-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"type":          "response.output_text.delta",
					"item_id":       "msg_1",
					"output_index":  0,
					"content_index": 0,
					"delta":         text,
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					s, _ := d["delta"].(string)
					sb.WriteString(s)
				}
				return sb.String()
			},
		},
		{
			name:   "bedrock-converse-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"contentBlockDelta": map[string]any{
						"contentBlockIndex": 0,
						"delta":             map[string]any{"text": text},
					},
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					cbd, _ := d["contentBlockDelta"].(map[string]any)
					delta, _ := cbd["delta"].(map[string]any)
					s, _ := delta["text"].(string)
					sb.WriteString(s)
				}
				return sb.String()
			},
		},
		{
			name:   "openai-default-path",
			params: map[string]interface{}{"email": true},
			event: func(text string) string {
				ev, _ := json.Marshal(map[string]any{
					"choices": []any{map[string]any{
						"index": 0,
						"delta": map[string]any{"content": text},
					}},
				})
				return "data: " + string(ev) + "\n\n"
			},
			assemble: func(raw string) string {
				var sb strings.Builder
				for _, line := range strings.Split(raw, "\n") {
					if !strings.HasPrefix(line, "data: ") {
						continue
					}
					var d map[string]any
					if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &d) != nil {
						continue
					}
					chs, _ := d["choices"].([]any)
					for _, c := range chs {
						cm, _ := c.(map[string]any)
						delta, _ := cm["delta"].(map[string]any)
						s, _ := delta["content"].(string)
						sb.WriteString(s)
					}
				}
				return sb.String()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustGetPIIPolicy(t, tc.params)
			respCtx := streamingRespCtx("text/event-stream", map[string]string{"guest@example.com": "[EMAIL_0000]"})

			// Split the placeholder one character per event — the hard case.
			var stream strings.Builder
			for _, f := range []string{"mail ", "[", "E", "M", "A", "I", "L", "_", "0", "0", "0", "0", "]", " ok"} {
				stream.WriteString(tc.event(f))
			}

			out := driveResponseStream(t, p, respCtx, splitEvery(stream.String(), 40))

			if got, want := tc.assemble(out), "mail guest@example.com ok"; got != want {
				t.Errorf("assembled content mismatch\n got: %q\nwant: %q", got, want)
			}
			if strings.Contains(out, "[EMAIL_0000]") {
				t.Errorf("placeholder leaked to client:\n%s", out)
			}
		})
	}
}

// TestDefaultPaths_BindToExpectedShape pins which JSONPath each provider frame
// resolves to. The list is order-sensitive: "$.delta" is a deliberate trailing
// fallback for the OpenAI Responses API, and must never shadow the more
// specific paths above it — most importantly Anthropic's "$.delta.text".
func TestDefaultPaths_BindToExpectedShape(t *testing.T) {
	cases := []struct {
		name     string
		frame    string
		wantText string
		wantPath string
	}{
		{
			name:     "anthropic binds to $.delta.text, not the $.delta fallback",
			frame:    `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}`,
			wantText: "Hi",
			wantPath: "$.delta.text",
		},
		{
			name:     "openai responses api binds to the $.delta fallback",
			frame:    `{"type":"response.output_text.delta","output_index":0,"delta":"Hello"}`,
			wantText: "Hello",
			wantPath: "$.delta",
		},
		{
			name:     "openai chat completions binds to choices[0].delta.content",
			frame:    `{"choices":[{"index":0,"delta":{"content":"Hey"}}]}`,
			wantText: "Hey",
			wantPath: "$.choices[0].delta.content",
		},
		{
			name:     "bedrock converse binds to contentBlockDelta.delta.text",
			frame:    `{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Yo"}}}`,
			wantText: "Yo",
			wantPath: "$.contentBlockDelta.delta.text",
		},
		{
			name:     "gemini binds to candidates[0].content.parts[0].text",
			frame:    `{"candidates":[{"content":{"parts":[{"text":"Sup"}]}}]}`,
			wantText: "Sup",
			wantPath: "$.candidates[0].content.parts[0].text",
		},
		{
			name:     "an unrecognised shape matches nothing and is forwarded intact",
			frame:    `{"output":{"message":{"chunk":"Nope"}}}`,
			wantText: "",
			wantPath: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text, path := extractFirstDeltaContentKeyed(tc.frame, DefaultStreamingJSONPaths)
			if text != tc.wantText || path != tc.wantPath {
				t.Errorf("got (%q, %q), want (%q, %q)", text, path, tc.wantText, tc.wantPath)
			}
		})
	}
}
