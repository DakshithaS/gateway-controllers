# Prompt Compressor Policy

`prompt-compressor` compresses prompt text before the upstream LLM call.

## Use In `build.yaml`

Add the policy package under `policies:`:

```yaml
version: v1
policies:
  - name: prompt-compressor
    pipPackage: github.com/wso2/gateway-controllers/policies/prompt-compressor@v0
```

Use the policy in API configuration with the major-only version:

```yaml
policies:
  - name: prompt-compressor
    version: v0
```
