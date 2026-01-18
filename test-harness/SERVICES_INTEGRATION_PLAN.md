# Services Integration Implementation Plan

This document provides a detailed implementation plan for integrating the 5 unused services into the dashboard-api.

**Target Services:**
1. `alerting-engine.ts` → Alerting Module
2. `anomaly-detection.ts` → Monitoring Module
3. `audit-evidence.ts` → Compliance Module (extend existing)
4. `policy-testing-framework.ts` → Policy Validation Module (extend existing)
5. `realtime-ingestion.ts` → Unified Findings Module (extend existing)

---

## Phase 1: Alerting Engine Integration

### 1.1 Module Structure

**New Module:** `dashboard-api/src/alerting/`

```
alerting/
├── alerting.module.ts
├── alerting.service.ts
├── alerting.controller.ts
├── dto/
│   ├── create-alert-rule.dto.ts
│   ├── update-alert-rule.dto.ts
│   ├── create-alert-channel.dto.ts
│   ├── update-alert-channel.dto.ts
│   └── alert-query.dto.ts
├── entities/
│   ├── alert-rule.entity.ts
│   ├── alert-channel.entity.ts
│   └── alert.entity.ts
└── alerting.service.spec.ts
```

### 1.2 Implementation Steps

#### Step 1.1: Create Alerting Module
- Create `alerting.module.ts` with imports from `notifications`, `unified-findings`
- Register `AlertingEngine` as provider
- Export service and controller

#### Step 1.2: Create Entities
- `alert-rule.entity.ts` - Map AlertRule interface to entity
- `alert-channel.entity.ts` - Map AlertChannel interface to entity
- `alert.entity.ts` - Map Alert interface to entity
- Add persistence layer (JSON file or database)

#### Step 1.3: Create DTOs
- `create-alert-rule.dto.ts` - Validation for rule creation
- `update-alert-rule.dto.ts` - Validation for rule updates
- `create-alert-channel.dto.ts` - Validation for channel creation
- `update-alert-channel.dto.ts` - Validation for channel updates
- `alert-query.dto.ts` - Query parameters for alert history

#### Step 1.4: Create Service
- `alerting.service.ts`:
  - Initialize `AlertingEngine` instance
  - Load rules and channels from storage
  - Implement CRUD operations for rules and channels
  - Wire up event listeners for findings
  - Integrate with `NotificationsService` for delivery
  - Handle alert aggregation and cooldown

#### Step 1.5: Create Controller
- `alerting.controller.ts`:
  - `POST /api/alerting/rules` - Create alert rule
  - `GET /api/alerting/rules` - List alert rules
  - `GET /api/alerting/rules/:id` - Get alert rule
  - `PUT /api/alerting/rules/:id` - Update alert rule
  - `DELETE /api/alerting/rules/:id` - Delete alert rule
  - `POST /api/alerting/rules/:id/test` - Test alert rule
  - `POST /api/alerting/channels` - Create alert channel
  - `GET /api/alerting/channels` - List alert channels
  - `PUT /api/alerting/channels/:id` - Update alert channel
  - `DELETE /api/alerting/channels/:id` - Delete alert channel
  - `GET /api/alerting/alerts` - Query alert history
  - `GET /api/alerting/alerts/:id` - Get alert details
  - `POST /api/alerting/alerts/:id/retry` - Retry failed alert

#### Step 1.6: Integrate with Unified Findings
- Modify `unified-findings.service.ts`:
  - Inject `AlertingService`
  - Call `alertingService.evaluateFinding()` when new finding is created
  - Trigger alerts on finding updates (severity changes, status changes)

#### Step 1.7: Integrate with Notifications
- Modify `notifications.service.ts`:
  - Add channel delivery methods (email, Slack, PagerDuty, Teams, webhook)
  - Implement retry logic for failed deliveries
  - Track delivery status

### 1.3 Dependencies

**Required Imports:**
- `AlertingEngine`, `AlertRule`, `AlertChannel`, `Alert` from `services/alerting-engine`
- `UnifiedFinding` from `core/unified-finding-schema`
- `NotificationsService` from `notifications/notifications.service`
- `UnifiedFindingsService` from `unified-findings/unified-findings.service`

**Module Dependencies:**
- `NotificationsModule`
- `UnifiedFindingsModule`

### 1.4 Testing Requirements

- Unit tests for service methods
- Integration tests for alert rule evaluation
- E2E tests for alert delivery
- Test alert aggregation and cooldown
- Test multi-channel delivery

---

## Phase 2: Anomaly Detection Integration

### 2.1 Module Structure

**New Module:** `dashboard-api/src/monitoring/`

```
monitoring/
├── monitoring.module.ts
├── monitoring.service.ts
├── monitoring.controller.ts
├── dto/
│   ├── anomaly-query.dto.ts
│   ├── anomaly-config.dto.ts
│   └── anomaly-response.dto.ts
├── entities/
│   └── anomaly.entity.ts
└── monitoring.service.spec.ts
```

### 2.2 Implementation Steps

#### Step 2.1: Create Monitoring Module
- Create `monitoring.module.ts`
- Import `UnifiedFindingsModule` and `ComplianceModule`
- Register `AnomalyDetectionService` as provider
- Export service and controller

#### Step 2.2: Create Entities
- `anomaly.entity.ts` - Map Anomaly interface to entity
- Add persistence for anomaly history

#### Step 2.3: Create DTOs
- `anomaly-query.dto.ts` - Query parameters for anomalies
- `anomaly-config.dto.ts` - Configuration for anomaly detection
- `anomaly-response.dto.ts` - Response format for anomalies

#### Step 2.4: Create Service
- `monitoring.service.ts`:
  - Initialize `AnomalyDetectionService` instance
  - Load finding history from `UnifiedFindingsService`
  - Implement anomaly detection triggers:
    - On new finding creation
    - Scheduled batch analysis (cron job)
    - On-demand analysis
  - Store detected anomalies
  - Integrate with `AlertingService` to trigger alerts on anomalies
  - Provide anomaly history and trends

#### Step 2.5: Create Controller
- `monitoring.controller.ts`:
  - `GET /api/monitoring/anomalies` - Query anomalies
  - `GET /api/monitoring/anomalies/:id` - Get anomaly details
  - `POST /api/monitoring/anomalies/analyze` - Trigger analysis
  - `GET /api/monitoring/anomalies/types/:type` - Get anomalies by type
  - `GET /api/monitoring/patterns` - Get finding patterns
  - `GET /api/monitoring/risk-spikes` - Get risk spikes
  - `GET /api/monitoring/compliance-drift` - Get compliance drift
  - `GET /api/monitoring/attack-patterns` - Get attack patterns
  - `PUT /api/monitoring/config` - Update detection config

#### Step 2.6: Integrate with Unified Findings
- Modify `unified-findings.service.ts`:
  - Inject `MonitoringService`
  - Call `monitoringService.analyzeFinding()` when new finding is created
  - Provide finding history to monitoring service

#### Step 2.7: Integrate with Alerting
- Modify `alerting.service.ts`:
  - Add method to create alert from anomaly
  - Auto-create alert rules for critical anomalies

#### Step 2.8: Scheduled Analysis
- Create scheduled task (cron job):
  - Run anomaly detection daily/hourly
  - Analyze finding patterns
  - Detect compliance drift
  - Identify attack patterns

### 2.3 Dependencies

**Required Imports:**
- `AnomalyDetectionService`, `Anomaly`, `AnomalyDetectionConfig` from `services/anomaly-detection`
- `UnifiedFinding` from `core/unified-finding-schema`
- `UnifiedFindingsService` from `unified-findings/unified-findings.service`
- `ComplianceService` from `compliance/compliance.service`
- `AlertingService` from `alerting/alerting.service`

**Module Dependencies:**
- `UnifiedFindingsModule`
- `ComplianceModule`
- `AlertingModule` (after Phase 1)

### 2.4 Testing Requirements

- Unit tests for anomaly detection logic
- Integration tests for pattern detection
- Test risk spike detection
- Test compliance drift detection
- Test attack pattern detection
- Test scheduled analysis

---

## Phase 3: Audit Evidence Integration

### 3.1 Module Structure

**Extend Existing Module:** `dashboard-api/src/compliance/`

```
compliance/
├── ... (existing files)
├── audit-evidence.service.ts (NEW)
├── audit-evidence.controller.ts (NEW)
├── dto/
│   ├── create-audit-event.dto.ts (NEW)
│   ├── create-evidence.dto.ts (NEW)
│   ├── create-attestation.dto.ts (NEW)
│   └── audit-query.dto.ts (NEW)
└── entities/
    ├── audit-event.entity.ts (NEW)
    ├── evidence.entity.ts (NEW)
    └── attestation.entity.ts (NEW)
```

### 3.2 Implementation Steps

#### Step 3.1: Create Audit Evidence Service
- `audit-evidence.service.ts`:
  - Initialize `AuditEvidenceService` instance
  - Implement audit event recording
  - Implement evidence collection
  - Implement compliance report generation
  - Implement attestation workflows
  - Integrate with existing `ComplianceService`

#### Step 3.2: Create Entities
- `audit-event.entity.ts` - Map AuditEvent interface to entity
- `evidence.entity.ts` - Map Evidence interface to entity
- `attestation.entity.ts` - Map Attestation interface to entity

#### Step 3.3: Create DTOs
- `create-audit-event.dto.ts` - Validation for audit event creation
- `create-evidence.dto.ts` - Validation for evidence collection
- `create-attestation.dto.ts` - Validation for attestation creation
- `audit-query.dto.ts` - Query parameters for audit logs

#### Step 3.4: Create Controller
- `audit-evidence.controller.ts`:
  - `POST /api/compliance/audit-events` - Record audit event
  - `GET /api/compliance/audit-events` - Query audit events
  - `GET /api/compliance/audit-events/:id` - Get audit event
  - `POST /api/compliance/evidence` - Collect evidence
  - `GET /api/compliance/evidence` - Query evidence
  - `GET /api/compliance/evidence/:id` - Get evidence
  - `DELETE /api/compliance/evidence/:id` - Delete evidence (if expired)
  - `POST /api/compliance/attestations` - Create attestation
  - `GET /api/compliance/attestations` - Query attestations
  - `GET /api/compliance/attestations/:id` - Get attestation
  - `POST /api/compliance/attestations/:id/approve` - Approve attestation
  - `POST /api/compliance/attestations/:id/reject` - Reject attestation
  - `POST /api/compliance/reports` - Generate compliance report
  - `GET /api/compliance/reports` - List compliance reports
  - `GET /api/compliance/reports/:id` - Get compliance report
  - `GET /api/compliance/reports/:id/download` - Download report

#### Step 3.5: Integrate with Existing Services
- Modify `policies.service.ts`:
  - Record audit events on policy changes
  - Collect evidence for policy changes
- Modify `compliance.service.ts`:
  - Use `AuditEvidenceService` for compliance checks
  - Link evidence to compliance controls
- Modify `test-results.service.ts`:
  - Record audit events on test execution
  - Collect evidence for test results

#### Step 3.6: Auto-Collection Hooks
- Create middleware/interceptors:
  - Auto-record audit events for policy changes
  - Auto-record audit events for test execution
  - Auto-collect evidence for compliance checks

### 3.3 Dependencies

**Required Imports:**
- `AuditEvidenceService`, `AuditEvent`, `Evidence`, `Attestation`, `ComplianceReport` from `services/audit-evidence`
- `ComplianceService` from `compliance/compliance.service`
- `PoliciesService` from `policies/policies.service`
- `TestResultsService` from `test-results/test-results.service`

**Module Dependencies:**
- `ComplianceModule` (existing)
- `PoliciesModule`
- `TestResultsModule`

### 3.4 Testing Requirements

- Unit tests for audit event recording
- Unit tests for evidence collection
- Unit tests for attestation workflows
- Integration tests for compliance report generation
- Test audit log querying and filtering
- Test evidence expiration

---

## Phase 4: Policy Testing Framework Integration

### 4.1 Module Structure

**Extend Existing Module:** `dashboard-api/src/policy-validation/`

```
policy-validation/
├── ... (existing files)
├── policy-testing.service.ts (NEW)
├── policy-testing.controller.ts (NEW)
├── dto/
│   ├── run-unit-tests.dto.ts (NEW)
│   ├── run-regression-tests.dto.ts (NEW)
│   ├── run-performance-tests.dto.ts (NEW)
│   └── policy-test-result.dto.ts (NEW)
└── entities/
    └── policy-test-result.entity.ts (NEW)
```

### 4.2 Implementation Steps

#### Step 4.1: Create Policy Testing Service
- `policy-testing.service.ts`:
  - Initialize `PolicyTestingFramework` instance
  - Inject `PolicyDecisionPoint` service
  - Implement unit test execution
  - Implement regression test execution
  - Implement performance test execution
  - Store test results

#### Step 4.2: Create Entities
- `policy-test-result.entity.ts` - Map PolicyTestResult interface to entity

#### Step 4.3: Create DTOs
- `run-unit-tests.dto.ts` - Validation for unit test execution
- `run-regression-tests.dto.ts` - Validation for regression test execution
- `run-performance-tests.dto.ts` - Validation for performance test execution
- `policy-test-result.dto.ts` - Response format for test results

#### Step 4.4: Create Controller
- `policy-testing.controller.ts`:
  - `POST /api/policy-validation/:policyId/tests/unit` - Run unit tests
  - `POST /api/policy-validation/:policyId/tests/regression` - Run regression tests
  - `POST /api/policy-validation/:policyId/tests/performance` - Run performance tests
  - `GET /api/policy-validation/:policyId/tests/results` - Get test results
  - `GET /api/policy-validation/:policyId/tests/results/:resultId` - Get test result
  - `POST /api/policy-validation/tests/suites` - Create test suite
  - `GET /api/policy-validation/tests/suites` - List test suites
  - `GET /api/policy-validation/tests/suites/:id` - Get test suite
  - `PUT /api/policy-validation/tests/suites/:id` - Update test suite
  - `DELETE /api/policy-validation/tests/suites/:id` - Delete test suite

#### Step 4.5: Integrate with Policy Validation
- Modify `policy-validation.service.ts`:
  - Add test execution to policy validation workflow
  - Store baseline results for regression testing
  - Integrate test results into validation reports

#### Step 4.6: Integrate with Policies
- Modify `policies.service.ts`:
  - Auto-run tests on policy creation/update
  - Store test results with policy versions
  - Block policy deployment if tests fail (optional)

### 4.3 Dependencies

**Required Imports:**
- `PolicyTestingFramework`, `PolicyTestSuite`, `PolicyTestResult`, `PolicyPerformanceMetrics` from `services/policy-testing-framework`
- `PolicyDecisionPoint` from `services/policy-decision-point`
- `ABACPolicy` from `core/types`
- `PolicyValidationService` from `policy-validation/policy-validation.service`
- `PoliciesService` from `policies/policies.service`

**Module Dependencies:**
- `PolicyValidationModule` (existing)
- `PoliciesModule`

### 4.4 Testing Requirements

- Unit tests for policy test execution
- Integration tests for regression testing
- Performance tests for policy evaluation
- Test baseline comparison
- Test test suite management

---

## Phase 5: Real-Time Ingestion Integration

### 5.1 Module Structure

**Extend Existing Module:** `dashboard-api/src/unified-findings/`

```
unified-findings/
├── ... (existing files)
├── realtime-ingestion.service.ts (NEW)
├── realtime-ingestion.controller.ts (NEW)
├── dto/
│   ├── webhook-payload.dto.ts (NEW)
│   └── ingestion-config.dto.ts (NEW)
└── guards/
    └── webhook-auth.guard.ts (NEW)
```

### 5.2 Implementation Steps

#### Step 5.1: Create Real-Time Ingestion Service
- `realtime-ingestion.service.ts`:
  - Initialize `RealtimeIngestionService` instance
  - Inject `NormalizationEngine` and `EnhancedRiskScorer`
  - Implement webhook payload processing
  - Handle batch processing
  - Emit events for real-time updates
  - Integrate with `UnifiedFindingsService` to save findings

#### Step 5.2: Create DTOs
- `webhook-payload.dto.ts` - Validation for webhook payloads
- `ingestion-config.dto.ts` - Configuration for ingestion service

#### Step 5.3: Create Webhook Authentication Guard
- `webhook-auth.guard.ts`:
  - Validate webhook signatures (if scanner supports)
  - Validate API keys/tokens
  - Rate limiting for webhook endpoints

#### Step 5.4: Create Controller
- `realtime-ingestion.controller.ts`:
  - `POST /api/unified-findings/webhooks/:scannerId` - Webhook endpoint for scanner
  - `POST /api/unified-findings/webhooks/generic` - Generic webhook endpoint
  - `GET /api/unified-findings/ingestion/status` - Get ingestion status
  - `PUT /api/unified-findings/ingestion/config` - Update ingestion config
  - `GET /api/unified-findings/ingestion/events` - Get ingestion events (SSE or polling)

#### Step 5.5: Integrate with Unified Findings
- Modify `unified-findings.service.ts`:
  - Inject `RealtimeIngestionService`
  - Use ingestion service for webhook processing
  - Emit real-time events for frontend updates

#### Step 5.6: Integrate with Monitoring
- Modify `monitoring.service.ts`:
  - Trigger anomaly detection on new findings from ingestion
  - Analyze real-time finding patterns

#### Step 5.7: Integrate with Alerting
- Modify `alerting.service.ts`:
  - Evaluate alerts on new findings from ingestion
  - Trigger real-time alerts

#### Step 5.8: Webhook Documentation
- Create webhook documentation:
  - Supported scanners
  - Webhook payload formats
  - Authentication methods
  - Rate limits

### 5.3 Dependencies

**Required Imports:**
- `RealtimeIngestionService`, `WebhookPayload`, `IngestionConfig`, `IngestionEvent` from `services/realtime-ingestion`
- `NormalizationEngine` from `services/normalization-engine`
- `EnhancedRiskScorer` from `services/enhanced-risk-scorer`
- `UnifiedFindingsService` from `unified-findings/unified-findings.service`
- `MonitoringService` from `monitoring/monitoring.service`
- `AlertingService` from `alerting/alerting.service`

**Module Dependencies:**
- `UnifiedFindingsModule` (existing)
- `MonitoringModule` (after Phase 2)
- `AlertingModule` (after Phase 1)

### 5.4 Testing Requirements

- Unit tests for webhook processing
- Integration tests for normalization and risk scoring
- Test batch processing
- Test event emission
- Test webhook authentication
- Test rate limiting
- Load testing for webhook endpoints

---

## Phase 6: Cross-Integration & Event Flow

### 6.1 Event Flow Architecture

```
Webhook → RealtimeIngestionService
  ↓
NormalizationEngine → UnifiedFinding
  ↓
EnhancedRiskScorer → Risk Score
  ↓
UnifiedFindingsService.save()
  ↓
┌─────────────────────────────────┐
│  Parallel Event Processing      │
└─────────────────────────────────┘
  ├─→ AlertingService.evaluate()
  ├─→ MonitoringService.analyze()
  └─→ AuditEvidenceService.record()
```

### 6.2 Integration Points

1. **Unified Findings → Alerting**
   - New finding → Evaluate alert rules → Send alerts

2. **Unified Findings → Monitoring**
   - New finding → Analyze for anomalies → Store anomalies → Trigger alerts

3. **Unified Findings → Audit Evidence**
   - New finding → Record audit event → Collect evidence

4. **Policy Changes → Audit Evidence**
   - Policy change → Record audit event → Collect evidence

5. **Test Execution → Audit Evidence**
   - Test execution → Record audit event → Collect evidence

6. **Anomaly Detection → Alerting**
   - Anomaly detected → Create alert → Send notification

### 6.3 Event Bus (Optional Enhancement)

Consider implementing an event bus for decoupled communication:
- Use NestJS EventEmitter or message queue (Redis, RabbitMQ)
- Publish events: `finding.created`, `finding.updated`, `anomaly.detected`, `alert.triggered`
- Subscribe to events in respective services

---

## Phase 7: Frontend Integration

### 7.1 Alerting UI

**New Views:**
- `dashboard-frontend/src/views/Alerting.vue`
  - Alert rules management
  - Alert channels configuration
  - Alert history
  - Alert statistics

**Components:**
- `AlertRuleForm.vue` - Create/edit alert rules
- `AlertChannelForm.vue` - Create/edit alert channels
- `AlertHistory.vue` - Alert history table
- `AlertStatistics.vue` - Alert metrics

### 7.2 Monitoring UI

**New Views:**
- `dashboard-frontend/src/views/Monitoring.vue`
  - Anomaly dashboard
  - Risk spike visualization
  - Compliance drift charts
  - Attack pattern detection

**Components:**
- `AnomalyList.vue` - List of detected anomalies
- `RiskSpikeChart.vue` - Risk spike visualization
- `ComplianceDriftChart.vue` - Compliance drift over time
- `AttackPatternDetection.vue` - Attack pattern visualization

### 7.3 Audit Evidence UI (Extend Compliance)

**Extend Existing:**
- `dashboard-frontend/src/views/Compliance.vue`
  - Add "Audit Logs" tab
  - Add "Evidence" tab
  - Add "Attestations" tab

**Components:**
- `AuditLogViewer.vue` - Audit log table with filtering
- `EvidenceManager.vue` - Evidence collection and management
- `AttestationWorkflow.vue` - Attestation creation and approval

### 7.4 Policy Testing UI (Extend Policy Validation)

**Extend Existing:**
- `dashboard-frontend/src/views/PolicyValidation.vue`
  - Add "Testing" tab

**Components:**
- `PolicyTestRunner.vue` - Run policy tests
- `PolicyTestResults.vue` - View test results
- `PolicyTestSuiteManager.vue` - Manage test suites

### 7.5 Real-Time Updates

**WebSocket/SSE Integration:**
- Connect to ingestion events endpoint
- Real-time updates for:
  - New findings
  - Anomaly detections
  - Alert triggers
  - Compliance score changes

---

## Phase 8: Testing & Validation

### 8.1 Unit Tests

**Coverage Requirements:**
- Each service: >80% coverage
- All DTOs: Validation tests
- All controllers: Request/response tests

### 8.2 Integration Tests

**Test Scenarios:**
1. Webhook → Ingestion → Normalization → Risk Scoring → Storage
2. New Finding → Alert Evaluation → Alert Delivery
3. New Finding → Anomaly Detection → Anomaly Storage → Alert
4. Policy Change → Audit Event → Evidence Collection
5. Policy Update → Test Execution → Test Results

### 8.3 E2E Tests

**Test Flows:**
1. Create alert rule → Receive finding → Alert triggered → Notification sent
2. Configure anomaly detection → Receive findings → Anomaly detected → Alert triggered
3. Create attestation → Approve attestation → Evidence linked
4. Run policy tests → View results → Baseline comparison

### 8.4 Performance Tests

**Load Testing:**
- Webhook endpoint: 1000 requests/second
- Alert evaluation: 100 alerts/second
- Anomaly detection: Batch of 10,000 findings
- Policy testing: 100 policies, 1000 test cases

---

## Phase 9: Documentation

### 9.1 API Documentation

**Update OpenAPI/Swagger:**
- Document all new endpoints
- Include request/response examples
- Document authentication requirements
- Document rate limits

### 9.2 Integration Guides

**Create Guides:**
- Webhook integration guide for scanners
- Alert rule configuration guide
- Anomaly detection configuration guide
- Policy testing guide
- Audit evidence collection guide

### 9.3 User Documentation

**Update User Guides:**
- Alerting setup and configuration
- Monitoring and anomaly detection
- Compliance reporting with evidence
- Policy testing workflows

---

## Implementation Timeline

### Week 1-2: Phase 1 (Alerting Engine)
- Days 1-3: Module structure, entities, DTOs
- Days 4-6: Service implementation
- Days 7-9: Controller implementation
- Days 10-12: Integration with unified findings and notifications
- Days 13-14: Testing

### Week 3-4: Phase 2 (Anomaly Detection)
- Days 1-3: Module structure, entities, DTOs
- Days 4-6: Service implementation
- Days 7-9: Controller implementation
- Days 10-12: Integration with unified findings and alerting
- Days 13-14: Testing and scheduled analysis

### Week 5: Phase 3 (Audit Evidence)
- Days 1-2: Service implementation
- Days 3-4: Controller implementation
- Days 5-7: Integration with existing services
- Days 8-9: Auto-collection hooks
- Days 10-11: Testing

### Week 6: Phase 4 (Policy Testing)
- Days 1-2: Service implementation
- Days 3-4: Controller implementation
- Days 5-6: Integration with policy validation
- Days 7-8: Testing

### Week 7: Phase 5 (Real-Time Ingestion)
- Days 1-2: Service implementation
- Days 3-4: Controller and webhook endpoints
- Days 5-6: Integration with unified findings
- Days 7-8: Integration with monitoring and alerting
- Days 9-10: Testing and documentation

### Week 8: Phase 6-7 (Cross-Integration & Frontend)
- Days 1-3: Cross-service integration
- Days 4-7: Frontend UI implementation
- Days 8-10: Real-time updates

### Week 9: Phase 8-9 (Testing & Documentation)
- Days 1-4: Comprehensive testing
- Days 5-7: API documentation
- Days 8-10: User guides and integration docs

**Total Estimated Time: 9 weeks**

---

## Dependencies & Prerequisites

### Required Services
- ✅ `NormalizationEngine` - Already integrated
- ✅ `EnhancedRiskScorer` - Already integrated
- ✅ `PolicyDecisionPoint` - Already integrated
- ✅ `NotificationsService` - Already exists
- ✅ `UnifiedFindingsService` - Already exists
- ✅ `ComplianceService` - Already exists
- ✅ `PolicyValidationService` - Already exists

### Required Infrastructure
- Storage for alert rules, channels, anomalies, audit events, evidence, attestations
- Webhook endpoint infrastructure
- Event emission infrastructure (optional: message queue)

### Required Configuration
- Alert channel credentials (email, Slack, PagerDuty, Teams)
- Webhook authentication keys
- Anomaly detection thresholds
- Audit retention policies

---

## Risk Mitigation

### Risk 1: Service Dependencies
**Mitigation:** Implement services in order (Phase 1 → 5), with proper dependency injection

### Risk 2: Performance Impact
**Mitigation:** 
- Use async processing for alert evaluation
- Batch anomaly detection
- Implement rate limiting for webhooks

### Risk 3: Data Storage
**Mitigation:**
- Start with JSON file storage (existing pattern)
- Design entities for easy migration to database later

### Risk 4: Frontend Complexity
**Mitigation:**
- Implement backend APIs first
- Frontend can be added incrementally
- Use existing UI patterns

---

## Success Criteria

### Phase 1 (Alerting)
- ✅ Alert rules can be created and managed via API
- ✅ Alerts are triggered on finding events
- ✅ Alerts are delivered via configured channels
- ✅ Alert aggregation and cooldown work correctly

### Phase 2 (Monitoring)
- ✅ Anomalies are detected on new findings
- ✅ Risk spikes are identified
- ✅ Compliance drift is monitored
- ✅ Attack patterns are detected

### Phase 3 (Audit Evidence)
- ✅ Audit events are recorded for policy/test changes
- ✅ Evidence can be collected and linked to compliance controls
- ✅ Attestations can be created and approved
- ✅ Compliance reports include evidence

### Phase 4 (Policy Testing)
- ✅ Unit tests can be run on policies
- ✅ Regression tests compare baseline vs current
- ✅ Performance tests measure evaluation time
- ✅ Test results are stored and queryable

### Phase 5 (Real-Time Ingestion)
- ✅ Webhooks accept scanner payloads
- ✅ Findings are normalized and risk-scored in real-time
- ✅ Events are emitted for real-time updates
- ✅ Integration with monitoring and alerting works

---

## Next Steps

1. **Review and Approve Plan** - Get stakeholder approval
2. **Set Up Development Environment** - Ensure all dependencies are available
3. **Create Feature Branches** - One branch per phase
4. **Begin Phase 1** - Start with alerting engine integration
5. **Regular Reviews** - Weekly progress reviews and adjustments

---

**Document Version:** 1.0  
**Last Updated:** [Current Date]  
**Status:** Ready for Implementation
