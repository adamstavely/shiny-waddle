# Phase 4: API Endpoint Usage Analysis - CORRECTED

## Summary

After thorough analysis of frontend code, many endpoints previously marked as "unused" are actually **being called**. This document provides the corrected analysis.

## Actually Used Endpoints (Previously Marked as Unused)

### ✅ Confirmed Used Endpoints

1. **`api/ticketing`** ✅ **USED**
   - `TicketingIntegrations.vue` calls:
     - `GET /api/ticketing/integrations`
     - `POST /api/ticketing/integrations`
     - `PATCH /api/ticketing/integrations/:id`
     - `DELETE /api/ticketing/integrations/:id`
     - `POST /api/ticketing/integrations/:id/test`
   - `ViolationDetailModal.vue` calls:
     - `GET /api/ticketing/tickets?violationId=:id`
     - `GET /api/ticketing/integrations`
     - `GET /api/ticketing/integrations/:id/tickets`

2. **`api/history`** ✅ **USED**
   - `History.vue` calls:
     - `GET /api/history/executions`
     - `GET /api/history/audit-logs`
     - `GET /api/history/activities`
     - `GET /api/history/executions/:id`

3. **`api/sla`** ✅ **USED**
   - `SLAManagement.vue` calls:
     - `GET /api/sla/policies`
     - `GET /api/sla/violations`
     - `GET /api/sla/stats`
     - `POST /api/sla/policies`
     - `PATCH /api/sla/policies/:id`
     - `DELETE /api/sla/policies/:id`
     - `POST /api/sla/violations/:id/resolve`

4. **`api/policy-validation`** ✅ **USED**
   - `PolicyValidation.vue` calls:
     - `POST /api/policy-validation/detect-conflicts`
     - `POST /api/policy-validation/analyze-coverage`
     - `POST /api/policy-validation/test-performance`

5. **`api/scheduled-reports`** ✅ **USED**
   - `ScheduledReports.vue` calls:
     - `GET /api/scheduled-reports`
     - `POST /api/scheduled-reports`
     - `PUT /api/scheduled-reports/:id`
     - `PATCH /api/scheduled-reports/:id/toggle`
     - `POST /api/scheduled-reports/:id/run-now`
     - `DELETE /api/scheduled-reports/:id`
   - `GenerateReportModal.vue` calls:
     - `POST /api/scheduled-reports`

6. **`api/distributed-systems`** ✅ **USED**
   - `DistributedTestModal.vue` calls:
     - `POST /api/distributed-systems/tests/run`
   - `RegionConfigModal.vue` calls:
     - `GET /api/distributed-systems/regions`
     - `POST /api/distributed-systems/regions`
     - `PATCH /api/distributed-systems/regions/:id`

7. **`api/identity-providers`** ✅ **USED**
   - `IdentityProviders.vue` calls:
     - `POST /api/identity-providers/test-ad-group`
     - `POST /api/identity-providers/test-okta-policy`
     - `POST /api/identity-providers/test-auth0-policy`
     - `POST /api/identity-providers/test-azure-ad-conditional-access`
     - `POST /api/identity-providers/test-gcp-iam-binding`

8. **`api/platform-config`** ✅ **USED** (partial)
   - `Policies.vue` calls:
     - `GET /api/platform-config/baselines`

## Actually Unused Endpoints

### ⚠️ Truly Unused Endpoints

1. **`api/data-pipeline`** ⚠️ **NOT USED**
   - `DataPipelines.vue` exists but **NO API calls found**
   - View has UI but doesn't fetch data from backend
   - **Should be calling**: `GET /api/data-pipeline`, `POST /api/data-pipeline`, etc.

2. **`api/api-gateway`** ⚠️ **NOT USED**
   - `APIGatewayConfigForm.vue` exists but no API calls found
   - Configuration form exists but doesn't save/fetch from backend

3. **`api/rls-cls`** ⚠️ **NOT USED**
   - `RLSCLSConfigForm.vue` exists but no API calls found
   - Configuration form exists but doesn't save/fetch from backend

4. **`api/network-policy`** ⚠️ **NOT USED**
   - `NetworkPolicyConfigForm.vue` exists but no API calls found
   - Configuration form exists but doesn't save/fetch from backend

5. **`api/dlp`** ⚠️ **NOT USED**
   - `DLPConfigForm.vue` exists but no API calls found
   - Configuration form exists but doesn't save/fetch from backend

6. **`api/v1/compliance-snapshots`** ⚠️ **NOT USED**
   - No frontend views found that use this endpoint

7. **`api/v1/exceptions`** ⚠️ **NOT USED**
   - `ExceptionsPolicies.vue` exists but uses `/api/policies/exceptions` instead
   - Backend endpoint may be redundant

8. **`api/v1/security`** ⚠️ **NOT USED**
   - No frontend views found that use this endpoint directly

9. **`api/v1/risk-scoring`** ⚠️ **NOT USED**
   - No frontend views found that use this endpoint directly

10. **`api/alerting`** ⚠️ **NOT USED**
    - No frontend views found that use this endpoint
    - Alerting functionality may be handled elsewhere

11. **`api/integrations/iam`** ⚠️ **NOT USED**
    - `IAMIntegrations.vue` exists but uses `/api/integrations/sso`, `/api/integrations/rbac`, `/api/integrations/idp` instead
    - Backend endpoint may be redundant or for different purpose

12. **`api/integrations/siem`** ⚠️ **NOT USED**
    - No frontend views found that use this endpoint

13. **`api/integrations/cloud-providers`** ⚠️ **NOT USED**
    - No frontend views found that use this endpoint

14. **`api/v1/standards`** ⚠️ **NOT USED**
    - `Policies.vue` uses `/api/standards` instead (different route)
    - Backend endpoint may be redundant

15. **`api/v1/data-classification`** ⚠️ **NOT USED** (base route)
    - `Policies.vue` uses `/api/data-classification/levels` instead
    - Base route may not be needed

16. **`api/cicd`** ⚠️ **NOT USED** (base route)
    - `CICDSecurityGates.vue` uses `/api/cicd/security-gates` instead
    - Base route may not be needed

17. **`api/integrations`** ⚠️ **NOT USED** (base route)
    - Sub-routes are used (`/api/integrations/sso`, etc.)
    - Base route may not be needed

## Recommendations

### High Priority Fixes

1. **`DataPipelines.vue`** - **CRITICAL**: View exists but doesn't call backend
   - Add API calls to fetch pipeline configurations
   - Add API calls to save pipeline configurations
   - Add API calls to run pipeline tests
   - Should call: `GET /api/data-pipeline`, `POST /api/data-pipeline`, `POST /api/data-pipeline/:id/test`

2. **Configuration Forms Missing API Integration**:
   - `APIGatewayConfigForm.vue` - Add API calls to save/fetch configs
   - `RLSCLSConfigForm.vue` - Add API calls to save/fetch configs
   - `NetworkPolicyConfigForm.vue` - Add API calls to save/fetch configs
   - `DLPConfigForm.vue` - Add API calls to save/fetch configs

### Medium Priority

3. **Route Consolidation**:
   - Consider if `/api/v1/exceptions` and `/api/policies/exceptions` should be consolidated
   - Consider if `/api/v1/standards` and `/api/standards` should be consolidated
   - Consider if base routes like `/api/cicd` and `/api/integrations` are needed

### Low Priority

4. **Document Internal-Only Endpoints**:
   - `api/v1/security` - May be internal-only
   - `api/v1/risk-scoring` - May be internal-only
   - `api/alerting` - May be internal-only
   - `api/integrations/iam` - May be internal-only
   - `api/integrations/siem` - May be internal-only
   - `api/integrations/cloud-providers` - May be internal-only
   - `api/v1/compliance-snapshots` - May be internal-only

## Summary

**Previously Identified as Unused**: 22 endpoints
**Actually Unused**: ~17 endpoints
**Actually Used**: 5 endpoints (ticketing, history, sla, policy-validation, scheduled-reports, distributed-systems, identity-providers)

**Critical Issue**: `DataPipelines.vue` view exists but doesn't integrate with backend API!
