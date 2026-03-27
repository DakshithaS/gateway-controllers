package ratelimit

import (
	"testing"

	policyv1alpha2 "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
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

	ctx := &policyv1alpha2.ResponseContext{
		ResponseHeaders: policyv1alpha2.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policyv1alpha2.Body{
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

	ctx := &policyv1alpha2.ResponseContext{
		ResponseHeaders: policyv1alpha2.NewHeaders(map[string][]string{
			"content-type": {"application/json"},
		}),
		ResponseBody: &policyv1alpha2.Body{
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
