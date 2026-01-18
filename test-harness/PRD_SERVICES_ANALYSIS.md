# PRD Services Analysis & Implementation Gap Analysis

This document analyzes:
1. Unused services against PRD requirements to determine if they should be kept
2. Gaps between ASPM Enhancement Roadmap and PRD requirements

---

## Part 1: Unused Services vs PRD Requirements

### 1.1 `alerting-engine.ts` - **KEEP & INTEGRATE**

**PRD Requirements:**
- **WF-NOT-001**: System MUST support notifications (email, in-app, webhook)
- **WF-NOT-002**: System MUST deliver notifications reliably with retry
- **DEP-MON-003**: System MUST support alerting on errors, failures, performance degradation, security events
- **ROADMAP-001**: Real-time alerts on policy violations
- **SEC-AUDIT-002**: System MUST alert on suspicious audit events
- **WF-RISK-004**: System MUST alert on expiring risk acceptances
- **WF-REM-003**: System MUST alert on remediation deadlines

**ASPM Roadmap Status:** ✅ Marked as IMPLEMENTED

**Verdict:** ✅ **KEEP & INTEGRATE**
- **Required by PRD:** Yes - Multiple requirements for alerting/notifications
- **Status:** Implemented but not integrated into dashboard-api
- **Action:** Integrate into dashboard-api and wire up to notification system

---

### 1.2 `anomaly-detection.ts` - **KEEP & INTEGRATE**

**PRD Requirements:**
- **ROADMAP-001**: Anomaly detection for unusual access
- **NFR-SEC-005**: System MUST detect and alert on suspicious activity
- **16.1.1 Real-Time Monitoring**: Anomaly detection for unusual access
- **ROADMAP-004**: Anomaly detection (Advanced Analytics)

**ASPM Roadmap Status:** ✅ Marked as IMPLEMENTED

**Verdict:** ✅ **KEEP & INTEGRATE**
- **Required by PRD:** Yes - Explicitly mentioned in roadmap and security monitoring
- **Status:** Implemented but not integrated into dashboard-api
- **Action:** Integrate into dashboard-api and connect to real-time monitoring

---

### 1.3 `audit-evidence.ts` - **KEEP & INTEGRATE**

**PRD Requirements:**
- **SEC-AUDIT-001**: System MUST log all security-relevant events (audit trail)
- **SEC-AUDIT-002**: System MUST support audit log export, search, filtering
- **FR-UI-009**: System MUST export audit logs and evidence
- **1.3 Target Users**: Auditors need to review compliance evidence and audit trails
- **3.1.1 Data Steward**: Compliance reporting and audit trails
- **3.1.2 Cyber Risk Manager**: Comprehensive audit logs
- **3.2.1 Compliance Officer**: Export audit logs and evidence

**ASPM Roadmap Status:** ✅ Marked as IMPLEMENTED

**Verdict:** ✅ **KEEP & INTEGRATE**
- **Required by PRD:** Yes - Critical for compliance and audit requirements
- **Status:** Implemented but not integrated into dashboard-api
- **Action:** Integrate into dashboard-api and connect to compliance module

---

### 1.4 `policy-testing-framework.ts` - **KEEP & INTEGRATE**

**PRD Requirements:**
- **FR-POL-006**: Policy Performance Testing - System MUST test policy evaluation performance
- **FR-POL-007**: Policy Regression Testing - System MUST run regression test suites
- **FR-POL-008**: Policy Change Simulation - System MUST simulate policy changes
- **FR-ZTA-ID-002**: Policy Validation - System MUST run policy regression tests
- **API Endpoints**: `/api/policy-validation/test-performance`, `/api/policy-validation/run-regression`

**ASPM Roadmap Status:** ✅ Marked as IMPLEMENTED

**Verdict:** ✅ **KEEP & INTEGRATE**
- **Required by PRD:** Yes - Explicit functional requirements for policy testing
- **Status:** Implemented but not integrated into dashboard-api
- **Action:** Integrate into dashboard-api policy-validation module

---

### 1.5 `realtime-ingestion.ts` - **KEEP & INTEGRATE**

**PRD Requirements:**
- **ROADMAP-001**: Real-time monitoring of access patterns
- **16.1.1 Real-Time Monitoring**: Real-time monitoring of access patterns
- **NFR-USE-002**: System MUST support real-time updates without full page refresh
- **REP-008**: System MUST display real-time compliance metrics
- **FR-UI-001**: System MUST display real-time compliance metrics

**ASPM Roadmap Status:** ✅ Marked as IMPLEMENTED

**Verdict:** ✅ **KEEP & INTEGRATE**
- **Required by PRD:** Yes - Real-time monitoring is a roadmap priority
- **Status:** Implemented but not integrated into dashboard-api
- **Action:** Integrate into dashboard-api and connect to webhook endpoints

---

### 1.6 `score-monitor.ts` - **DELETE**

**PRD Requirements:**
- **FR-UI-001**: System MUST display compliance scores (but no requirement for monitoring score changes)
- No explicit requirement for score change monitoring service

**ASPM Roadmap Status:** ❌ Not mentioned

**Issues:**
- Broken imports (wrong paths)
- Not used anywhere
- Functionality can be handled by existing compliance services

**Verdict:** ✅ **DELETE**
- **Required by PRD:** No - No explicit requirement
- **Status:** Broken and unused
- **Action:** Delete - Score monitoring can be handled by existing compliance/trend analysis services

---

## Part 2: ASPM Roadmap vs PRD Gap Analysis

### 2.1 Missing PRD Requirements Not in ASPM Roadmap

#### 2.1.1 Authentication & Authorization (Critical Gap)

**PRD Requirements:**
- **SEC-AUTH-001**: Authentication mechanisms (SSO, MFA, password policies)
- **SEC-AUTH-002**: Session management
- **SEC-AUTHZ-001**: RBAC with roles (Admin, Data Steward, Cyber Risk Manager, Developer, Viewer)
- **SEC-AUTHZ-002**: Permission enforcement
- **NFR-SEC-001**: Authentication
- **NFR-SEC-002**: Authorization

**ASPM Roadmap Status:** ❌ Not mentioned in roadmap

**Gap:** Critical - Authentication/authorization is required for production but not in ASPM roadmap

**Priority:** P1 - Critical

---

#### 2.1.2 Database Migration

**PRD Requirements:**
- **TECH-DEBT-001**: Migrate from JSON files to proper database
- **NFR-SCAL-002**: Data scalability requirements
- **DEP-ENV-002**: Database support (PostgreSQL, MySQL)

**ASPM Roadmap Status:** ❌ Not mentioned in roadmap

**Gap:** Critical - Current JSON file storage doesn't scale

**Priority:** P1 - Critical

---

#### 2.1.3 API Versioning

**PRD Requirements:**
- **8.5 Versioning**: URL path versioning (e.g., `/api/v1/...`)
- **NFR-INT-001**: API versioning

**ASPM Roadmap Status:** ❌ Not mentioned in roadmap

**Gap:** High - Required for API stability

**Priority:** P2 - High

---

#### 2.1.4 Rate Limiting

**PRD Requirements:**
- **8.4 Rate Limiting**: Rate limiting based on user roles and endpoint criticality
- **NFR-PERF-001**: API performance requirements

**ASPM Roadmap Status:** ❌ Not mentioned in roadmap

**Gap:** High - Required for production API

**Priority:** P2 - High

---

#### 2.1.5 Ephemeral Environment Automation

**PRD Requirements:**
- **FR-CICD-004**: Per-PR environments with automated creation/cleanup
- **4.5.4 Ephemeral Environments**: Full automation required

**ASPM Roadmap Status:** ⏳ Framework exists but automation not integrated

**Gap:** Medium - Code exists but not integrated with CI/CD

**Priority:** P2 - High

---

#### 2.1.6 Asset Inventory & Discovery

**PRD Requirements:**
- **2.1 Asset Registry**: Comprehensive asset registry
- **2.2 Discovery Mechanisms**: Auto-discover applications from Git, CI/CD, cloud providers
- **2.3 Asset Relationship Mapping**: Dependency graphs, service maps

**ASPM Roadmap Status:** ❌ Not implemented (mentioned in roadmap but not completed)

**Gap:** High - Required for ASPM but not implemented

**Priority:** P2 - High

---

#### 2.1.7 Threat Intelligence Integration

**PRD Requirements:**
- **6.1 Threat Intelligence Sources**: CVE feeds, exploit intelligence
- **6.2 Threat Correlation**: Map findings to known exploits
- **6.3 Threat-Aware Prioritization**: Boost priority for actively exploited vulnerabilities

**ASPM Roadmap Status:** ❌ Not implemented (mentioned but not completed)

**Gap:** Medium - Enhances risk scoring but not critical

**Priority:** P3 - Medium

---

#### 2.1.8 Finding Correlation & Deduplication

**PRD Requirements:**
- **11.1 Finding Correlation Engine**: Cross-scanner deduplication, related finding grouping
- **11.2 Attack Path Analysis**: Map vulnerabilities to attack paths

**ASPM Roadmap Status:** ⏳ Partially implemented (basic deduplication exists, correlation engine exists but attack path analysis pending)

**Gap:** Medium - Basic correlation exists, advanced features pending

**Priority:** P2 - High

---

#### 2.1.9 GraphQL API

**PRD Requirements:**
- **12.2 GraphQL API**: Flexible querying, real-time subscriptions, efficient data fetching

**ASPM Roadmap Status:** ❌ Not mentioned

**Gap:** Low - REST API exists, GraphQL is enhancement

**Priority:** P4 - Low

---

#### 2.1.10 Plugin System & SDKs

**PRD Requirements:**
- **12.3 Plugin System**: Custom scanner adapters, risk scoring models, workflows
- **12.4 SDKs**: JavaScript/TypeScript, Python, Go SDKs, CLI tools

**ASPM Roadmap Status:** ⏳ Scanner adapters exist (plugin-like), but no formal SDK/plugin system

**Gap:** Medium - Extensibility important but not critical

**Priority:** P3 - Medium

---

### 2.2 ASPM Roadmap Items Not Explicitly in PRD

#### 2.2.1 Unified Security Data Model & Normalization

**ASPM Roadmap Status:** ✅ COMPLETED

**PRD Status:** ⚠️ Implied but not explicitly required

**Analysis:** PRD focuses on access control testing, but unified findings model is essential for ASPM. This is an enhancement beyond core PRD scope.

**Verdict:** ✅ Keep - Essential for ASPM even if not in PRD

---

#### 2.2.2 Advanced Analytics & Reporting

**ASPM Roadmap Status:** ✅ MOSTLY COMPLETED (predictive analytics placeholder)

**PRD Status:** ✅ Required (REP-001 through REP-008)

**Analysis:** PRD requires reporting and analytics. ASPM roadmap extends this with executive dashboards and scheduled reports.

**Verdict:** ✅ Aligned - ASPM extends PRD requirements

---

#### 2.2.3 Platform Security (Encryption, Secrets, Audit Logging)

**ASPM Roadmap Status:** ✅ MOSTLY COMPLETED

**PRD Status:** ✅ Required (SEC-ENC-001, SEC-ENC-002, SEC-AUDIT-001, SEC-AUDIT-002)

**Analysis:** PRD requires these security features. ASPM roadmap implements them.

**Verdict:** ✅ Aligned - ASPM implements PRD requirements

---

## Part 3: Summary & Recommendations

### 3.1 Unused Services - Action Items

| Service | PRD Required? | Action | Priority |
|---------|---------------|--------|----------|
| `alerting-engine.ts` | ✅ Yes | Integrate into dashboard-api | P1 - Critical |
| `anomaly-detection.ts` | ✅ Yes | Integrate into dashboard-api | P1 - Critical |
| `audit-evidence.ts` | ✅ Yes | Integrate into dashboard-api | P1 - Critical |
| `policy-testing-framework.ts` | ✅ Yes | Integrate into dashboard-api | P2 - High |
| `realtime-ingestion.ts` | ✅ Yes | Integrate into dashboard-api | P2 - High |
| `score-monitor.ts` | ❌ No | Delete | Immediate |

### 3.2 Missing PRD Requirements - Implementation Gaps

| Requirement | PRD Section | ASPM Status | Priority |
|-------------|-------------|-------------|----------|
| Authentication & Authorization | SEC-AUTH-001, SEC-AUTHZ-001 | ❌ Not in roadmap | P1 - Critical |
| Database Migration | TECH-DEBT-001 | ❌ Not in roadmap | P1 - Critical |
| API Versioning | 8.5 Versioning | ❌ Not in roadmap | P2 - High |
| Rate Limiting | 8.4 Rate Limiting | ❌ Not in roadmap | P2 - High |
| Ephemeral Environment Automation | FR-CICD-004 | ⏳ Partial | P2 - High |
| Asset Inventory & Discovery | 2.1-2.3 | ❌ Not implemented | P2 - High |
| Finding Correlation (Advanced) | 11.1-11.2 | ⏳ Partial | P2 - High |
| Threat Intelligence | 6.1-6.3 | ❌ Not implemented | P3 - Medium |
| GraphQL API | 12.2 | ❌ Not mentioned | P4 - Low |
| Plugin System & SDKs | 12.3-12.4 | ⏳ Partial | P3 - Medium |

### 3.3 Recommended Next Steps

#### Immediate Actions (P1 - Critical)
1. **Integrate Unused Services:**
   - Wire up `alerting-engine.ts` to notification system
   - Integrate `anomaly-detection.ts` into real-time monitoring
   - Connect `audit-evidence.ts` to compliance module
   - Integrate `policy-testing-framework.ts` into policy-validation module
   - Connect `realtime-ingestion.ts` to webhook endpoints

2. **Delete Broken Service:**
   - Remove `score-monitor.ts` (functionality covered by existing services)

3. **Implement Critical Missing Features:**
   - Authentication & Authorization system
   - Database migration from JSON files

#### Short-term Actions (P2 - High)
1. Implement API versioning
2. Add rate limiting
3. Complete ephemeral environment automation
4. Implement asset inventory & discovery
5. Enhance finding correlation with attack path analysis

#### Medium-term Actions (P3 - Medium)
1. Threat intelligence integration
2. Formal plugin system
3. SDK development

#### Long-term Actions (P4 - Low)
1. GraphQL API
2. Advanced visualization features

---

## Part 4: Integration Plan for Unused Services

### 4.1 Alerting Engine Integration

**Target Module:** `dashboard-api/src/notifications/`

**Integration Steps:**
1. Import `AlertingEngine` from `services/alerting-engine.ts`
2. Create alert rules from notification preferences
3. Wire up to notification service
4. Add API endpoints for alert rule management
5. Connect to finding/violation events

**Files to Modify:**
- `dashboard-api/src/notifications/notifications.service.ts`
- `dashboard-api/src/notifications/notifications.controller.ts`
- `dashboard-api/src/unified-findings/unified-findings.service.ts` (trigger alerts)

---

### 4.2 Anomaly Detection Integration

**Target Module:** `dashboard-api/src/unified-findings/` or new `dashboard-api/src/monitoring/`

**Integration Steps:**
1. Import `AnomalyDetectionService` from `services/anomaly-detection.ts`
2. Initialize with finding history
3. Run anomaly detection on new findings
4. Trigger alerts when anomalies detected
5. Add API endpoints for anomaly queries

**Files to Modify:**
- `dashboard-api/src/unified-findings/unified-findings.service.ts`
- Create `dashboard-api/src/monitoring/monitoring.service.ts`
- Create `dashboard-api/src/monitoring/monitoring.controller.ts`

---

### 4.3 Audit Evidence Integration

**Target Module:** `dashboard-api/src/compliance/`

**Integration Steps:**
1. Import `AuditEvidenceService` from `services/audit-evidence.ts`
2. Connect to compliance module
3. Auto-collect evidence on compliance checks
4. Add API endpoints for evidence management
5. Integrate with compliance reports

**Files to Modify:**
- `dashboard-api/src/compliance/compliance.service.ts`
- `dashboard-api/src/compliance/compliance.controller.ts`
- `dashboard-api/src/policies/policies.service.ts` (audit policy changes)

---

### 4.4 Policy Testing Framework Integration

**Target Module:** `dashboard-api/src/policy-validation/`

**Integration Steps:**
1. Import `PolicyTestingFramework` from `services/policy-testing-framework.ts`
2. Add endpoints for policy testing
3. Integrate with policy validation service
4. Add UI for policy test execution

**Files to Modify:**
- `dashboard-api/src/policy-validation/policy-validation.service.ts`
- `dashboard-api/src/policy-validation/policy-validation.controller.ts`

---

### 4.5 Real-Time Ingestion Integration

**Target Module:** `dashboard-api/src/unified-findings/`

**Integration Steps:**
1. Import `RealtimeIngestionService` from `services/realtime-ingestion.ts`
2. Create webhook endpoint for scanner results
3. Process incoming findings in real-time
4. Trigger normalization and risk scoring
5. Emit events for dashboard updates

**Files to Modify:**
- `dashboard-api/src/unified-findings/unified-findings.controller.ts` (add webhook endpoint)
- `dashboard-api/src/unified-findings/unified-findings.service.ts` (integrate ingestion)

---

## Conclusion

**Key Findings:**
1. **5 of 6 unused services are REQUIRED by PRD** - They need to be integrated, not deleted
2. **1 service (`score-monitor.ts`) should be deleted** - Broken and not required
3. **Critical gaps exist** - Authentication, database migration, API versioning, rate limiting not in ASPM roadmap
4. **ASPM roadmap extends PRD** - Many ASPM features are enhancements beyond core PRD scope

**Recommended Priority:**
1. **Immediate:** Integrate unused services, delete broken service, implement authentication
2. **Short-term:** Database migration, API versioning, rate limiting, asset discovery
3. **Medium-term:** Threat intelligence, plugin system, enhanced correlation
4. **Long-term:** GraphQL API, advanced visualizations
