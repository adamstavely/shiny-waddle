# Services Usage Analysis

This document analyzes all services in the `test-harness/services/` directory to identify which are used and which are unused.

## Summary

**Total Services:** 60+ TypeScript service files  
**Exported from index.ts:** 18 services  
**Used in codebase:** ~50 services  
**Potentially Unused:** 6 services

---

## Services Exported from index.ts (Public API)

These services are part of the public API and should be kept even if not used internally:

1. ✅ `AccessControlTester` - Used in core/test-harness.ts
2. ✅ `DatasetHealthTester` - Used in core/test-harness.ts
3. ✅ `ComplianceReporter` - Used in core/test-harness.ts, src/run-tests.ts, examples
4. ✅ `PolicyDecisionPoint` - Used in validators, examples, dashboard-api
5. ✅ `QueryAnalyzer` - Exported (public API)
6. ✅ `PiiMaskingValidator` - Exported (public API)
7. ✅ `ABACPolicyLoader` - Used in src/run-tests.ts, examples
8. ✅ `RealSystemIntegration` - Exported (public API)
9. ✅ `AdvancedQueryAnalyzer` - Exported (public API)
10. ✅ `RiskScorer` - Exported (public API)
11. ✅ `PolicyVersioning` - Exported (public API)
12. ✅ `ComplianceTrendAnalyzer` - Exported (public API)
13. ✅ `AdvancedReporter` - Exported (public API)
14. ✅ `ServiceMeshIntegration` - Exported (public API)
15. ✅ `PolicyLanguageSupport` - Exported (public API)
16. ✅ `APISecurityTester` - Used in dashboard-api, examples
17. ✅ `DataPipelineTester` - Used in dashboard-api, examples
18. ✅ `DistributedSystemsTester` - Used in dashboard-api, examples

---

## Services Used in Dashboard API

These services are actively used by the dashboard API:

1. ✅ `RLSCLSTester` - Used in dashboard-api/src/rls-cls/
2. ✅ `DLPTester` - Used in dashboard-api/src/dlp/
3. ✅ `APIGatewayTester` - Used in dashboard-api/src/api-gateway/
4. ✅ `NetworkMicrosegmentationTester` - Used in dashboard-api/src/network-policy/
5. ✅ `IdentityProviderTester` - Used in dashboard-api/src/identity-providers/
6. ✅ `CICDSecurityGates` - Used in dashboard-api/src/cicd/
7. ✅ `NIST800207Compliance` - Used in dashboard-api/src/compliance/
8. ✅ `PolicyValidationTester` - Used in dashboard-api/src/policy-validation/
9. ✅ `SalesforceExperienceCloudTester` - Used in dashboard-api/src/salesforce-experience-cloud/
10. ✅ `DataPipelineTester` - Used in dashboard-api/src/data-pipeline/
11. ✅ `APISecurityTester` - Used in dashboard-api/src/api-security/
12. ✅ `DistributedSystemsTester` - Used in dashboard-api/src/distributed-systems/
13. ✅ `SIEMIntegration` - Used in dashboard-api/src/integrations/siem/
14. ✅ `IAMIntegration` - Used in dashboard-api/src/integrations/iam/
15. ✅ `MultiCloudIntegration` - Used in dashboard-api/src/integrations/cloud-provider/
16. ✅ `NormalizationEngine` - Used in dashboard-api/src/unified-findings/
17. ✅ `ECSAdapter` - Used in dashboard-api/src/unified-findings/
18. ✅ `EnhancedRiskScorer` - Used in dashboard-api/src/unified-findings/
19. ✅ `FindingCorrelationEngine` - Used in dashboard-api/src/unified-findings/
20. ✅ `AttackPathAnalyzer` - Used in dashboard-api/src/unified-findings/
21. ✅ `PolicyAsCode` - Used in dashboard-api/src/policy-validation/

---

## Services Used by Other Services

These services are used internally by other services:

1. ✅ `ContainerSecurityScanner` - Used by cicd-security-gates.ts
2. ✅ `K8sRBACValidator` - Used by cicd-security-gates.ts
3. ✅ `IACScanner` - Used by cicd-security-gates.ts
4. ✅ `ABACAttributeValidator` - Used by abac-correctness-validator.ts
5. ✅ `ABACCompletenessTester` - Used by abac-correctness-validator.ts
6. ✅ `ABACPerformanceTester` - Used by abac-correctness-validator.ts
7. ✅ `ABACConflictTester` - Used by abac-correctness-validator.ts
8. ✅ `ABACPropagationTester` - Used by abac-correctness-validator.ts (if exists)
9. ✅ `EnvironmentConfigValidator` - Used in examples, test suites
10. ✅ `SecretsManagementValidator` - Used in examples, test suites
11. ✅ `ConfigDriftDetector` - Used in examples, test suites
12. ✅ `EnvironmentPolicyValidator` - Used in examples, test suites
13. ✅ `APIVersioningTester` - Used in test suites
14. ✅ `APIGatewayPolicyValidator` - Used in test suites
15. ✅ `WebhookSecurityTester` - Used in test suites
16. ✅ `GraphQLSecurityValidator` - Used in test suites
17. ✅ `APIContractSecurityTester` - Used in test suites

---

## Potentially Unused Services

These services are **NOT imported or used anywhere** in the codebase:

### 1. ⚠️ `alerting-engine.ts` - **UNUSED**
- **Status**: Not imported anywhere
- **Purpose**: Alerting engine for real-time notifications
- **Mentioned in**: ASPM_ENHANCEMENT_ROADMAP.md (marked as implemented)
- **Action**: ⚠️ **REVIEW** - May be planned for future use or incorrectly marked as implemented

### 2. ⚠️ `anomaly-detection.ts` - **UNUSED**
- **Status**: Not imported anywhere
- **Purpose**: Anomaly detection service
- **Mentioned in**: ASPM_ENHANCEMENT_ROADMAP.md (marked as implemented)
- **Action**: ⚠️ **REVIEW** - May be planned for future use or incorrectly marked as implemented

### 3. ⚠️ `audit-evidence.ts` - **UNUSED**
- **Status**: Not imported anywhere
- **Purpose**: Audit evidence collection service
- **Mentioned in**: ASPM_ENHANCEMENT_ROADMAP.md (marked as implemented)
- **Action**: ⚠️ **REVIEW** - May be planned for future use or incorrectly marked as implemented

### 4. ⚠️ `policy-testing-framework.ts` - **UNUSED**
- **Status**: Not imported anywhere
- **Purpose**: Policy testing framework
- **Mentioned in**: ASPM_ENHANCEMENT_ROADMAP.md (marked as implemented)
- **Action**: ⚠️ **REVIEW** - May be planned for future use or incorrectly marked as implemented

### 5. ⚠️ `realtime-ingestion.ts` - **UNUSED**
- **Status**: Not imported anywhere
- **Purpose**: Real-time finding ingestion service
- **Mentioned in**: ASPM_ENHANCEMENT_ROADMAP.md (marked as implemented)
- **Action**: ⚠️ **REVIEW** - May be planned for future use or incorrectly marked as implemented

### 6. ⚠️ `score-monitor.ts` - **UNUSED & BROKEN**
- **Status**: Not imported anywhere, has incorrect imports
- **Purpose**: Monitors compliance score changes
- **Issues**: 
  - Imports from `../dashboard-api/src/` which is incorrect path
  - Should import from `../../dashboard-api/src/` or use dependency injection
- **Action**: ✅ **DELETE** - Broken and unused

---

## Services Used in Examples/Documentation

These services are referenced in examples or documentation (keep as examples):

1. ✅ All services in `examples/` directory
2. ✅ Services mentioned in `docs/api/SERVICES.md`
3. ✅ Services mentioned in `docs/guides/USER_GUIDE.md`

---

## Services Used in Test Suites

These services are used in test suite implementations:

1. ✅ `EnvironmentConfigTestSuite` - Used in examples
2. ✅ `ABACCorrectnessTestSuite` - Used in examples
3. ✅ All services in `services/test-suites/` directory

---

## Services Used in Validators

These services are used by validators:

1. ✅ `ABACAttributeValidator` - Used in abac-correctness-validator.ts
2. ✅ `ABACCompletenessTester` - Used in abac-correctness-validator.ts
3. ✅ `ABACPerformanceTester` - Used in abac-correctness-validator.ts
4. ✅ `ABACConflictTester` - Used in abac-correctness-validator.ts
5. ✅ `PolicyDecisionPoint` - Used in abac-correctness-validator.ts
6. ✅ `SalesforceExperienceCloudTester` - Used in salesforce-experience-cloud-validator.ts

---

## Scanner Adapters (All Used)

All scanner adapters in `services/scanner-adapters/` are used by `NormalizationEngine`:

1. ✅ `SonarQubeAdapter`
2. ✅ `SnykAdapter`
3. ✅ `SonatypeIQAdapter`
4. ✅ `OWASPZAPAdapter`
5. ✅ `CheckovAdapter`
6. ✅ `TrivyAdapter`
7. ✅ `ClairAdapter`
8. ✅ `AWSSecurityHubAdapter`
9. ✅ `AzureSecurityCenterAdapter` (if exists)
10. ✅ `GCPSecurityCommandCenterAdapter` (if exists)

---

## Payloads (All Used)

All payload files in `services/payloads/` are used by injection test suites:

1. ✅ `sql-injection.ts`
2. ✅ `nosql-injection.ts`
3. ✅ `xss.ts`
4. ✅ `command-injection.ts`
5. ✅ `path-traversal.ts`
6. ✅ `ssrf.ts`
7. ✅ `template-injection.ts`
8. ✅ `xxe.ts`

---

## Utils (All Used)

All utility files in `services/utils/` are used by various services:

1. ✅ `credential-detector.ts`
2. ✅ `header-analyzer.ts`
3. ✅ `jwt-validator.ts`
4. ✅ `pii-detector.ts`

---

## Recommendations

### Immediate Actions

1. **Delete `score-monitor.ts`** ✅ **SAFE TO DELETE**
   - Broken imports
   - Not used anywhere
   - Can be recreated if needed

### Review Before Deleting

2. **Review ASPM services** (5 services):
   - `alerting-engine.ts`
   - `anomaly-detection.ts`
   - `audit-evidence.ts`
   - `policy-testing-framework.ts`
   - `realtime-ingestion.ts`
   
   **Status**: These are marked as "IMPLEMENTED" in ASPM_ENHANCEMENT_ROADMAP.md but are not actually imported/used anywhere.
   
   **Options**:
   - **Option A**: Delete if they're not actually implemented/used
   - **Option B**: Integrate them if they're meant to be used but just not wired up yet
   - **Option C**: Keep if they're meant for future use

   **Recommendation**: Check with product team - if these are truly implemented, they should be integrated. If not, update the roadmap and delete them.

### Keep All Others

All other services are actively used and should be kept.

---

## Summary Table

| Service | Status | Used By | Action |
|---------|--------|---------|--------|
| score-monitor.ts | ❌ Unused & Broken | None | ✅ DELETE |
| alerting-engine.ts | ⚠️ Unused | None (marked implemented in roadmap) | ⚠️ REVIEW |
| anomaly-detection.ts | ⚠️ Unused | None (marked implemented in roadmap) | ⚠️ REVIEW |
| audit-evidence.ts | ⚠️ Unused | None (marked implemented in roadmap) | ⚠️ REVIEW |
| policy-testing-framework.ts | ⚠️ Unused | None (marked implemented in roadmap) | ⚠️ REVIEW |
| realtime-ingestion.ts | ⚠️ Unused | None (marked implemented in roadmap) | ⚠️ REVIEW |
| All other services | ✅ Used | Various | ✅ KEEP |

---

## Notes

- Services exported from `index.ts` are part of the public API and should be kept even if not used internally
- Services used in examples serve as documentation
- Services used in test suites are part of the testing infrastructure
- Scanner adapters are dynamically loaded by NormalizationEngine
- Payloads and utils are used by various services
