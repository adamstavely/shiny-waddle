# Phase 4: API Endpoint Usage Analysis

## Summary

This document tracks the analysis of backend API endpoints to identify unused or rarely used endpoints.

## Circular Dependencies Analysis

### Findings

**Circular Dependencies Handled**:
- ✅ `ApplicationsModule` uses `forwardRef()` for multiple modules:
  - TestResultsModule
  - SecurityModule
  - ValidatorsModule
  - TestHarnessesModule
  - TestBatteriesModule

**Dynamic Imports Used to Avoid Circular Dependencies**:
- `test-suites.service.ts`: Uses dynamic import for `TestHarnessesService` in `getUsedInHarnesses()`
- `policies.service.ts`: Uses dynamic import and `ModuleRef` for `TestsService` in `findTestsUsingPolicy()`

**Services Using forwardRef**:
- `rls-cls.service.ts`: Uses `forwardRef(() => ApplicationsService)`

### Status

✅ **Circular dependencies are properly handled** - No issues found. The codebase uses:
- `forwardRef()` for module-level circular dependencies
- Dynamic imports for service-level circular dependencies
- `ModuleRef` for runtime service resolution

## API Endpoint Inventory

### Backend Controllers (54 total)

1. `api/data-pipeline` - DataPipelineController
2. `api/api-gateway` - APIGatewayController
3. `api/rls-cls` - RLSCLSController
4. `api/network-policy` - NetworkPolicyController
5. `api/dlp` - DLPController
6. `api/policies` - PoliciesController
7. `api/violations` - ViolationsController
8. `api/v1/standards` - StandardsMappingController
9. `api/v1/test-harnesses` - TestHarnessesController
10. `api/identity-providers` - IdentityProviderController
11. `api/v1/notifications` - NotificationsController
12. `api/v1/test-batteries` - TestBatteriesController
13. `api/validation-targets` - ValidationTargetsController
14. `api/validation-rules` - ValidationTargetsController (second route)
15. `api/v1/runs` - RunsController
16. `api/ticketing` - TicketingController
17. `api/v1/test-results` - TestResultsController
18. `api/api-security` - ApiSecurityController
19. `api/validators` - ValidatorsController
20. `api/salesforce-experience-cloud` - SalesforceExperienceCloudController
21. `api/sla` - SLAController
22. `api/v1/test-suites` - TestSuitesController
23. `api/v1/data-classification` - DataClassificationController
24. `api/v1/finding-approvals` - FindingApprovalsController
25. `api/v1/applications` - ApplicationsController
26. `api/history` - HistoryController
27. `api/unified-findings` - UnifiedFindingsController
28. `api/v1/users` - UsersController
29. `api/v1/remediation-tracking` - RemediationTrackingController
30. `api/scheduled-reports` - ScheduledReportsController
31. `api/integrations` - IntegrationsController
32. `api/v1/dashboard` - DashboardSSEController
33. `api/v1` - DashboardController
34. `api/cicd` - CICDController
35. `api/cicd/security-gates` - SecurityGatesController
36. `api/v1/compliance-snapshots` - ComplianceSnapshotsController
37. `api/v1/exceptions` - ExceptionsController
38. `api/v1/compliance` - ComplianceController
39. `api/v1/compliance-scores` - ComplianceScoresController
40. `api/compliance/nist-800-207` - NIST800207Controller
41. `api/tests` - TestsAliasController
42. `api/v1/tests` - TestsController
43. `api/policy-validation` - PolicyValidationController
44. `api/v1/auth` - AuthController
45. `api/v1/security` - SecurityController
46. `api/v1/risk-scoring` - RiskScoringController
47. `api/distributed-systems` - DistributedSystemsController
48. `api/environment-config` - EnvironmentConfigController
49. `api/alerting` - AlertingController
50. `api/v1/platform-config` - PlatformConfigController
51. `api/integrations/iam` - IAMController
52. `api/integrations/siem` - SIEMController
53. `api/integrations/cloud-providers` - CloudProviderController
54. Root controller - AppController

## Frontend API Usage Analysis

### Common Endpoint Patterns Found

From frontend code analysis, the following endpoint patterns are actively used:

- `/api/v1/applications` - ✅ Used extensively
- `/api/v1/test-suites` - ✅ Used
- `/api/v1/test-harnesses` - ✅ Used
- `/api/v1/test-batteries` - ✅ Used
- `/api/v1/test-results` - ✅ Used
- `/api/v1/runs` - ✅ Used
- `/api/v1/notifications` - ✅ Used
- `/api/v1/dashboard-data` - ✅ Used
- `/api/salesforce-experience-cloud/tests/*` - ✅ Used
- `/api/environment-config/*` - ✅ Used
- `/api/policies` - ✅ Used
- `/api/violations` - ✅ Used
- `/api/unified-findings` - ✅ Used
- `/api/v1/compliance` - ✅ Used
- `/api/v1/compliance-scores` - ✅ Used
- `/api/v1/finding-approvals` - ✅ Used
- `/api/v1/remediation-tracking` - ✅ Used
- `/api/v1/users` - ✅ Used
- `/api/v1/auth` - ✅ Used

### Verified Used Endpoints (from frontend grep analysis)

Based on frontend code analysis, these endpoints are actively used:

- ✅ `/api/v1/applications` - Used extensively (GET, POST, PATCH, DELETE)
- ✅ `/api/v1/test-suites` - Used (GET, POST, PUT)
- ✅ `/api/v1/test-harnesses` - Used (GET, POST)
- ✅ `/api/v1/test-batteries` - Used (GET, POST)
- ✅ `/api/v1/test-results` - Used (GET)
- ✅ `/api/v1/runs` - Used (GET)
- ✅ `/api/v1/notifications` - Used (GET)
- ✅ `/api/v1/dashboard-data` - Used (GET)
- ✅ `/api/salesforce-experience-cloud/tests/*` - Used (POST)
- ✅ `/api/environment-config/*` - Used (POST: validate, validate-secrets, validate-policies)
- ✅ `/api/policies` - Used extensively (GET, POST, PUT, DELETE)
- ✅ `/api/violations` - Used (GET, PATCH, DELETE)
- ✅ `/api/unified-findings` - Used (GET)
- ✅ `/api/v1/compliance` - Used extensively (GET: frameworks, mappings, assessments, roadmaps)
- ✅ `/api/v1/compliance-scores` - Used
- ✅ `/api/v1/finding-approvals` - Used (GET: pending)
- ✅ `/api/v1/remediation-tracking` - Used
- ✅ `/api/v1/users` - Used
- ✅ `/api/v1/auth` - Used
- ✅ `/api/validators` - Used (GET, POST, PATCH, DELETE)
- ✅ `/api/validation-targets` - Used (GET, POST, PATCH, DELETE)
- ✅ `/api/validation-rules` - Used (GET)
- ✅ `/api/cicd/security-gates` - Used (POST: check-gates)
- ✅ `/api/compliance/nist-800-207` - Used (POST: assess)
- ✅ `/api/tests` - Used (GET)
- ✅ `/api/v1/tests` - Used (GET)
- ✅ `/api/policies/*/test` - Used (POST)
- ✅ `/api/policies/*/versions` - Used (POST)
- ✅ `/api/policies/*/deploy` - Used (POST)
- ✅ `/api/policies/*/rollback` - Used (POST)
- ✅ `/api/policies/*/audit` - Used (GET)
- ✅ `/api/policies/*/tests` - Used (GET)
- ✅ `/api/policies/exceptions` - Used (GET)
- ✅ `/api/data-classification/levels` - Used (GET)
- ✅ `/api/platform-config/baselines` - Used (GET)
- ✅ `/api/standards` - Used (GET)
- ✅ `/api/data-contracts` - Used (GET)
- ✅ `/api/salesforce/baselines` - Used (GET)
- ✅ `/api/elastic/baselines` - Used (GET)
- ✅ `/api/idp/baselines` - Used (GET)
- ✅ `/api/integrations/sso` - Used (GET, POST)
- ✅ `/api/integrations/rbac` - Used (GET, POST)
- ✅ `/api/integrations/idp` - Used (GET, POST)
- ✅ `/api/banners` - Used (GET, POST, PATCH, DELETE) - Note: May be in different controller

### Potentially Unused Endpoints

These endpoints were NOT found in frontend code and may be unused:

- ⚠️ `api/data-pipeline` - No frontend usage found
- ⚠️ `api/api-gateway` - No frontend usage found
- ⚠️ `api/rls-cls` - No frontend usage found
- ⚠️ `api/network-policy` - No frontend usage found
- ⚠️ `api/dlp` - No frontend usage found
- ⚠️ `api/ticketing` - No frontend usage found
- ⚠️ `api/sla` - No frontend usage found
- ⚠️ `api/history` - No frontend usage found
- ⚠️ `api/scheduled-reports` - No frontend usage found
- ⚠️ `api/integrations` (base) - No frontend usage found (but sub-routes are used)
- ⚠️ `api/cicd` (base) - No frontend usage found (but security-gates is used)
- ⚠️ `api/v1/compliance-snapshots` - No frontend usage found
- ⚠️ `api/v1/exceptions` - No frontend usage found
- ⚠️ `api/policy-validation` - No frontend usage found
- ⚠️ `api/v1/security` - No frontend usage found
- ⚠️ `api/v1/risk-scoring` - No frontend usage found
- ⚠️ `api/distributed-systems` - No frontend usage found
- ⚠️ `api/alerting` - No frontend usage found
- ⚠️ `api/v1/platform-config` (base) - No frontend usage found (but baselines sub-route is used)
- ⚠️ `api/integrations/iam` - No frontend usage found
- ⚠️ `api/integrations/siem` - No frontend usage found
- ⚠️ `api/integrations/cloud-providers` - No frontend usage found
- ⚠️ `api/identity-providers` - No frontend usage found
- ⚠️ `api/v1/standards` - No frontend usage found (but `/api/standards` is used)
- ⚠️ `api/v1/data-classification` (base) - No frontend usage found (but levels sub-route is used)

**Note**: Some endpoints may be:
- Internal-only (not exposed to frontend)
- Used by other services/scripts
- Planned but not yet implemented in frontend
- Accessed via different route patterns

## Recommendations

1. **Complete Frontend Usage Analysis**: 
   - Extract all API calls from frontend codebase
   - Map each backend endpoint to frontend usage
   - Identify truly unused endpoints

2. **Documentation**:
   - Document which endpoints are internal-only (not exposed to frontend)
   - Mark endpoints that are planned but not yet implemented in frontend
   - Create API documentation for all active endpoints

3. **Deprecation Strategy**:
   - If endpoints are truly unused, mark them as deprecated
   - Provide migration path if functionality is moved
   - Remove deprecated endpoints after grace period

4. **Testing**:
   - Ensure all active endpoints have tests
   - Add integration tests for frontend-backend API contracts

## Next Steps

1. ⏳ Complete comprehensive frontend API call extraction
2. ⏳ Map backend endpoints to frontend usage
3. ⏳ Identify and document unused endpoints
4. ⏳ Create deprecation plan for unused endpoints
