module github.com/wso2/gateway-controllers/policies/opaque-token-auth

go 1.26.2

require github.com/wso2/api-platform/sdk/core v0.2.4

// TODO: temporary — the cache utility (utils/cache) is not yet in a published
// SDK release. Remove this replace and bump the require above to the released
// version before merging.
replace github.com/wso2/api-platform/sdk/core => ../../../api-platform/sdk/core
