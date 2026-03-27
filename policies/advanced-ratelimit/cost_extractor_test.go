package ratelimit

import (
	"testing"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func TestCostExtractor_ExtractResponseCostV2_PlainBody(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"usage":{"prompt_tokens":42}}`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from response body to succeed")
	}
	if cost != 42 {
		t.Fatalf("expected extracted cost to be 42, got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCostV2_FallsBackToDefault(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 7,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(`{"invalid json`),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if extracted {
		t.Fatal("expected extraction to fail for invalid JSON payload")
	}
	if cost != 7 {
		t.Fatalf("expected default cost 7, got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCostV2_SSEBody(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.prompt_tokens",
				Multiplier: 1,
			},
		},
	})

	sseBody := "data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n" +
		"data: {\"id\":\"chatcmpl-1\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":62,\"total_tokens\":162}}\n" +
		"data: [DONE]\n"

	ctx := &policy.ResponseContext{
		ResponseHeaders: policy.NewHeaders(map[string][]string{
			"content-type": {"text/event-stream"},
		}),
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(sseBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from SSE body to succeed")
	}
	if cost != 100 {
		t.Fatalf("expected extracted cost to be 100 (prompt_tokens), got %v", cost)
	}
}

func TestCostExtractor_ExtractResponseCostV2_SSEBody_CompletionTokens(t *testing.T) {
	extractor := NewCostExtractor(CostExtractionConfig{
		Enabled: true,
		Default: 0,
		Sources: []CostSource{
			{
				Type:       CostSourceResponseBody,
				JSONPath:   "$.usage.completion_tokens",
				Multiplier: 2,
			},
		},
	})

	sseBody := "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n" +
		"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"prompt_tokens\":50,\"completion_tokens\":30,\"total_tokens\":80}}\n" +
		"data: [DONE]\n"

	ctx := &policy.ResponseContext{
		ResponseBody: &policy.Body{
			Present: true,
			Content: []byte(sseBody),
		},
	}

	cost, extracted := extractor.ExtractResponseCost(ctx)
	if !extracted {
		t.Fatal("expected extraction from SSE body to succeed")
	}
	// 30 * 2 (multiplier) = 60
	if cost != 60 {
		t.Fatalf("expected extracted cost to be 60 (30 * 2), got %v", cost)
	}
}

func TestExtractFromSSEBodyBytes_NoMatch(t *testing.T) {
	sseBody := []byte(
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n" +
			"data: [DONE]\n",
	)
	_, ok := extractFromSSEBodyBytes(sseBody, "$.usage.prompt_tokens")
	if ok {
		t.Error("expected no match when SSE events don't have usage")
	}
}

func TestExtractFromBodyBytes_PlainJSON_StillWorks(t *testing.T) {
	body := []byte(`{"usage":{"prompt_tokens":42}}`)
	cost, ok := extractFromBodyBytes(body, "$.usage.prompt_tokens")
	if !ok {
		t.Fatal("expected extraction from plain JSON to succeed")
	}
	if cost != 42 {
		t.Fatalf("expected 42, got %v", cost)
	}
}
