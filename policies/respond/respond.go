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

package respond

import (
	"encoding/json"
	"fmt"

	policy "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// RespondPolicy implements immediate response functionality
// This policy terminates the request processing and returns an immediate response to the client
type RespondPolicy struct{}

var ins = &RespondPolicy{}

func GetPolicy(
	metadata policy.PolicyMetadata,
	params map[string]interface{},
) (policy.Policy, error) {
	return ins, nil
}

// configError returns a 500 error response for configuration issues
func configError(message string) policy.ImmediateResponse {
	errBody, _ := json.Marshal(map[string]string{
		"error":   "Configuration Error",
		"message": message,
	})
	return policy.ImmediateResponse{
		StatusCode: 500,
		Headers: map[string]string{
			"content-type": "application/json",
		},
		Body: errBody,
	}
}

// Mode returns the processing mode for this policy
func (p *RespondPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess, // Can use request headers for context
		RequestBodyMode:    policy.BodyModeSkip,      // Don't need request body
		ResponseHeaderMode: policy.HeaderModeSkip,    // Returns immediate response
		ResponseBodyMode:   policy.BodyModeSkip,      // Returns immediate response
	}
}

// OnRequest returns an immediate response to the client
func (p *RespondPolicy) OnRequest(ctx *policy.RequestContext, params map[string]interface{}) policy.RequestAction {
	// Extract statusCode (default to 200 OK)
	statusCode := 200
	if statusCodeRaw, ok := params["statusCode"]; ok {
		switch v := statusCodeRaw.(type) {
		case float64:
			statusCode = int(v)
		case int:
			statusCode = v
		}
	}

	// Extract body
	var body []byte
	if bodyRaw, ok := params["body"]; ok {
		switch v := bodyRaw.(type) {
		case string:
			body = []byte(v)
		case []byte:
			body = v
		}
	}

	// Extract headers with fail-fast validation
	headers := make(map[string]string)
	if headersRaw, ok := params["headers"]; ok {
		if headersList, ok := headersRaw.([]interface{}); ok {
			for i, headerRaw := range headersList {
				headerMap, ok := headerRaw.(map[string]interface{})
				if !ok {
					return configError(fmt.Sprintf("headers[%d] must be an object", i))
				}

				// Safe type assertion for name
				nameRaw, ok := headerMap["name"]
				if !ok {
					return configError(fmt.Sprintf("headers[%d] missing required 'name' field", i))
				}
				name, ok := nameRaw.(string)
				if !ok {
					return configError(fmt.Sprintf("headers[%d].name must be a string", i))
				}
				if name == "" {
					return configError(fmt.Sprintf("headers[%d].name cannot be empty", i))
				}

				// Safe type assertion for value
				valueRaw, ok := headerMap["value"]
				if !ok {
					return configError(fmt.Sprintf("headers[%d] missing required 'value' field", i))
				}
				value, ok := valueRaw.(string)
				if !ok {
					return configError(fmt.Sprintf("headers[%d].value must be a string", i))
				}

				headers[name] = value
			}
		}
	}

	// Return immediate response action
	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}
}

// OnResponse is not used by this policy (returns immediate response in request phase)
func (p *RespondPolicy) OnResponse(ctx *policy.ResponseContext, params map[string]interface{}) policy.ResponseAction {
	return nil // No response processing needed
}
