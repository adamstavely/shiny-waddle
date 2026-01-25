# Test Coverage Expansion Plan

**Status:** Draft  
**Created:** 2026-01-25  
**Target Completion:** Q2 2026

## Executive Summary

This plan outlines a comprehensive strategy to expand test coverage across all layers of the Heimdall Dashboard application. Current state: **14% unit test coverage** (8/58 services), **good E2E coverage** (9 controller test files), **no frontend tests**, and **limited integration tests**.

**Goals:**
- Achieve **80%+ unit test coverage** for backend services
- Add **comprehensive integration tests** for multi-service workflows
- Expand **E2E tests** to cover all critical user flows
- Establish **frontend testing infrastructure** with component and E2E tests
- Set up **CI/CD test gates** with coverage thresholds

---

## Current State Assessment

### Unit Tests
- **Coverage:** 8/58 services (14%)
- **Existing:** `rls-cls`, `identity-provider`, `dlp`, `security-gates`, `nist-800-207`, `policy-validation`, `api-gateway`, `network-policy`
- **Missing:** 50 services without unit tests

### Integration Tests
- **Coverage:** Limited (framework-level only)
- **Missing:** API-level integration tests, multi-service workflows, database integration tests

### E2E Tests
- **Coverage:** 9 controller test files
- **Existing:** Good coverage of major endpoints
- **Missing:** Authentication flows, complex workflows, database-backed scenarios

### Frontend Tests
- **Coverage:** None
- **Missing:** Component tests, E2E tests, test infrastructure

---

## Phase 1: Foundation & Infrastructure (Weeks 1-2)

### 1.1 Test Infrastructure Setup

**Tasks:**
- [ ] Add coverage thresholds to `jest.config.js` (80% minimum)
- [ ] Configure coverage reporting (HTML, JSON, LCOV)
- [ ] Set up test coverage badges/CI integration
- [ ] Create test utilities for common patterns (mocking, fixtures)
- [ ] Document testing standards and best practices

**Deliverables:**
- Updated `jest.config.js` with coverage thresholds
- Test utilities documentation
- Testing standards guide

### 1.2 Frontend Testing Infrastructure

**Tasks:**
- [ ] Install Vitest and Vue Test Utils
- [ ] Install Playwright for E2E testing
- [ ] Configure Vitest config file
- [ ] Configure Playwright config file
- [ ] Set up test scripts in `dashboard-frontend/package.json`
- [ ] Create component test utilities and helpers
- [ ] Create E2E test utilities and page objects

**Dependencies:**
```json
{
  "devDependencies": {
    "vitest": "^1.0.0",
    "@vue/test-utils": "^2.4.0",
    "@vitest/ui": "^1.0.0",
    "playwright": "^1.40.0",
    "@playwright/test": "^1.40.0",
    "jsdom": "^23.0.0"
  }
}
```

**Deliverables:**
- `dashboard-frontend/vitest.config.ts`
- `dashboard-frontend/playwright.config.ts`
- Test utilities and helpers
- Updated `package.json` with test scripts

---

## Phase 2: Unit Test Expansion (Weeks 3-8)

### 2.1 Priority Services (Weeks 3-4)

**High Priority Services** (Critical business logic):
- [ ] `auth.service.ts` - Authentication & authorization
- [ ] `policies.service.ts` - Policy management
- [ ] `tests.service.ts` - Test management
- [ ] `test-suites.service.ts` - Test suite management
- [ ] `test-harnesses.service.ts` - Test harness management
- [ ] `test-batteries.service.ts` - Test battery management
- [ ] `applications.service.ts` - Application management
- [ ] `compliance.service.ts` - Compliance scoring
- [ ] `violations.service.ts` - Violation management
- [ ] `users.service.ts` - User management

**Test Coverage Requirements:**
- Success cases (happy paths)
- Validation errors
- Service errors
- Edge cases
- Boundary conditions

**Target:** 10 services with 80%+ coverage

### 2.2 Secondary Services (Weeks 5-6)

**Medium Priority Services:**
- [ ] `alerting.service.ts`
- [ ] `environment-config.service.ts`
- [ ] `distributed-systems.service.ts`
- [ ] `risk-scoring/services/enhanced-risk-scoring.service.ts`
- [ ] `security/encryption.service.ts`
- [ ] `security/audit-log.service.ts`
- [ ] `security/secrets.service.ts`
- [ ] `test-discovery.service.ts`
- [ ] `compliance-scores.service.ts`
- [ ] `exceptions.service.ts`
- [ ] `policies/services/policy-versioning.service.ts`
- [ ] `data-pipeline.service.ts`
- [ ] `ticketing.service.ts`
- [ ] `remediation.service.ts`
- [ ] `remediation-tracking.service.ts`
- [ ] `unified-findings.service.ts`
- [ ] `integrations.service.ts`
- [ ] `scheduled-reports.service.ts`
- [ ] `notifications.service.ts`
- [ ] `finding-approvals.service.ts`
- [ ] `data-classification.service.ts`
- [ ] `standards-mapping.service.ts`
- [ ] `history.service.ts`
- [ ] `runs.service.ts`
- [ ] `test-results.service.ts`
- [ ] `validation-targets.service.ts`
- [ ] `validators.service.ts`
- [ ] `validator-discovery.service.ts`

**Target:** 28 services with 80%+ coverage

### 2.3 Controller Unit Tests (Week 7)

**Tasks:**
- [ ] Create unit tests for all 50 controllers
- [ ] Test request validation
- [ ] Test response formatting
- [ ] Test error handling
- [ ] Test authorization guards

**Priority Controllers:**
1. `auth.controller.ts`
2. `policies.controller.ts`
3. `tests.controller.ts`
4. `test-suites.controller.ts`
5. `test-harnesses.controller.ts`
6. `test-batteries.controller.ts`
7. `applications.controller.ts`
8. `compliance.controller.ts`
9. `violations.controller.ts`
10. `users.controller.ts`

**Target:** 50 controllers with unit tests

### 2.4 Utility & Middleware Tests (Week 8)

**Tasks:**
- [ ] Test common utilities
- [ ] Test middleware (version, sanitize, rate-limit, etc.)
- [ ] Test pipes (sanitize pipe)
- [ ] Test filters (exception filters)
- [ ] Test interceptors (user context)

**Target:** 100% coverage for utilities and middleware

---

## Phase 3: Integration Tests (Weeks 9-12)

### 3.1 Multi-Service Workflows (Weeks 9-10)

**Critical Workflows:**
- [ ] **Test Creation Flow:**
  - Create test → Add to suite → Assign to harness → Add to battery → Execute
- [ ] **Policy Management Flow:**
  - Create policy → Validate → Assign to application → Run tests → View results
- [ ] **Compliance Workflow:**
  - Run test battery → Generate findings → Create violations → Track remediation → Update compliance score
- [ ] **Application Onboarding:**
  - Create application → Add infrastructure → Assign test harness → Run initial tests → View dashboard
- [ ] **User Management Flow:**
  - Create user → Assign roles → Grant access → Test permissions → Audit logs

**Test Structure:**
```typescript
describe('Test Creation Workflow (Integration)', () => {
  it('should create test, add to suite, assign to harness, and execute', async () => {
    // 1. Create test
    // 2. Create suite with test
    // 3. Create harness with suite
    // 4. Create battery with harness
    // 5. Execute battery
    // 6. Verify results
  });
});
```

**Target:** 5 major workflows with integration tests

### 3.2 Database Integration Tests (Week 11)

**Tasks:**
- [ ] Set up test database (PostgreSQL test container)
- [ ] Test database migrations
- [ ] Test entity relationships
- [ ] Test transactions and rollbacks
- [ ] Test query performance
- [ ] Test data integrity constraints

**Tools:**
- `@testcontainers/postgresql` for test database
- Database seeding utilities
- Transaction rollback helpers

**Target:** Database operations fully tested

### 3.3 External Service Integration Tests (Week 12)

**Tasks:**
- [ ] Mock external APIs (Salesforce, Elastic, etc.)
- [ ] Test API client error handling
- [ ] Test retry logic
- [ ] Test rate limiting
- [ ] Test authentication flows
- [ ] Test webhook handling

**Tools:**
- `nock` for HTTP mocking
- `msw` (Mock Service Worker) for API mocking

**Target:** External integrations tested with mocks

---

## Phase 4: E2E Test Expansion (Weeks 13-16)

### 4.1 Authentication & Authorization E2E (Week 13)

**Tests:**
- [ ] User registration flow
- [ ] User login flow
- [ ] JWT token validation
- [ ] Role-based access control
- [ ] Permission checks
- [ ] Session management
- [ ] Password reset flow
- [ ] MFA flow (if applicable)

**Target:** Complete auth flows covered

### 4.2 Complex User Workflows E2E (Week 14)

**Workflows:**
- [ ] Create application → Configure infrastructure → Run tests → View results
- [ ] Create test suite → Add tests → Configure → Execute → View findings
- [ ] Create policy → Validate → Deploy → Monitor → Update
- [ ] View dashboard → Filter data → Export reports → Schedule reports
- [ ] Manage users → Assign roles → Grant permissions → Audit access

**Target:** 5 complex workflows covered

### 4.3 API Endpoint Coverage (Week 15)

**Missing Endpoints:**
- [ ] All CRUD operations for all entities
- [ ] Bulk operations
- [ ] Search and filtering
- [ ] Pagination
- [ ] Sorting
- [ ] Export functionality
- [ ] Import functionality

**Target:** 100% endpoint coverage

### 4.4 Error Scenarios E2E (Week 16)

**Scenarios:**
- [ ] Invalid input validation
- [ ] Unauthorized access attempts
- [ ] Resource not found
- [ ] Conflict errors
- [ ] Rate limiting
- [ ] Server errors
- [ ] Network failures

**Target:** All error scenarios covered

---

## Phase 5: Frontend Testing (Weeks 17-20)

### 5.1 Component Unit Tests (Weeks 17-18)

**Priority Components:**
1. **Forms:**
   - [ ] `BaseForm.vue`
   - [ ] `AccessControlTestForm.vue`
   - [ ] `DLPTestForm.vue`
   - [ ] `NetworkPolicyTestForm.vue`
   - [ ] `APISecurityTestForm.vue`

2. **Modals:**
   - [ ] `BaseModal.vue`
   - [ ] `TestModal.vue`
   - [ ] `TestSuiteBuilderModal.vue`
   - [ ] `TestBatteryModal.vue`
   - [ ] `TestHarnessModal.vue`

3. **Tables:**
   - [ ] `BaseTable.vue`
   - [ ] `TestResultsTable.vue`

4. **Charts:**
   - [ ] `BarChart.vue`
   - [ ] `LineChart.vue`
   - [ ] `ComplianceScoreGauge.vue`
   - [ ] `RiskHeatmap.vue`

5. **Navigation:**
   - [ ] `Sidebar.vue`
   - [ ] `Drawer.vue`
   - [ ] `Breadcrumb.vue`

**Test Coverage:**
- Component rendering
- Props validation
- Event handling
- Computed properties
- Watchers
- Slots
- Accessibility

**Target:** 50+ components with unit tests

### 5.2 Page Component Tests (Week 19)

**Priority Pages:**
- [ ] `Home.vue`
- [ ] `TestsOverview.vue`
- [ ] `TestCreate.vue`
- [ ] `TestSuites.vue`
- [ ] `TestHarnesses.vue`
- [ ] `TestBatteries.vue`
- [ ] `PoliciesOverview.vue`
- [ ] `AccessControlOverview.vue`
- [ ] `ComplianceOverview.vue`

**Test Coverage:**
- Page rendering
- Data loading
- User interactions
- Navigation
- Error states
- Loading states

**Target:** 20+ pages with tests

### 5.3 Frontend E2E Tests (Week 20)

**Critical User Flows:**
- [ ] User login → Navigate dashboard → View tests
- [ ] Create test → Configure → Save → View in list
- [ ] Create test suite → Add tests → Configure → Save
- [ ] Create test harness → Assign suites → Assign to application
- [ ] Create test battery → Configure execution → Run → View results
- [ ] View compliance dashboard → Filter by application → Export report
- [ ] Create policy → Validate → Deploy → View in policies list
- [ ] View violations → Filter → Remediate → Track progress

**Tools:**
- Playwright for E2E testing
- Page Object Model pattern
- Test data fixtures

**Target:** 10+ critical user flows covered

---

## Phase 6: CI/CD Integration & Quality Gates (Weeks 21-22)

### 6.1 CI/CD Test Integration

**Tasks:**
- [ ] Add test steps to GitHub Actions workflow
- [ ] Configure test coverage reporting
- [ ] Set up coverage badges
- [ ] Add test result artifacts
- [ ] Configure test failure notifications
- [ ] Set up parallel test execution

**Workflow Steps:**
```yaml
- name: Run Unit Tests
  run: npm run test:cov
  env:
    CI: true

- name: Run Integration Tests
  run: npm run test:integration

- name: Run E2E Tests
  run: npm run test:e2e

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage/lcov.info
```

**Target:** Full CI/CD test integration

### 6.2 Coverage Thresholds & Quality Gates

**Thresholds:**
- Unit tests: **80%** minimum coverage
- Integration tests: **70%** minimum coverage
- E2E tests: **100%** of critical flows
- Frontend component tests: **70%** minimum coverage

**Quality Gates:**
- Block PRs if coverage drops below threshold
- Require new code to have tests
- Enforce test coverage on modified files
- Generate coverage reports for each PR

**Target:** Automated quality gates in place

### 6.3 Test Reporting & Monitoring

**Tasks:**
- [ ] Set up test result dashboards
- [ ] Track test execution time
- [ ] Monitor flaky tests
- [ ] Generate test reports
- [ ] Track coverage trends

**Target:** Comprehensive test reporting

---

## Success Metrics

### Coverage Targets

| Test Type | Current | Target | Timeline |
|-----------|---------|--------|----------|
| Unit Tests (Services) | 14% (8/58) | 80%+ (46/58) | Week 8 |
| Unit Tests (Controllers) | 0% (0/50) | 80%+ (40/50) | Week 7 |
| Integration Tests | Limited | 5 workflows | Week 12 |
| E2E Tests (Backend) | 9 files | 20+ files | Week 16 |
| Frontend Component Tests | 0% | 70%+ (50+ components) | Week 19 |
| Frontend E2E Tests | 0 | 10+ flows | Week 20 |

### Quality Metrics

- **Test Execution Time:** < 5 minutes for unit tests, < 15 minutes for E2E
- **Test Reliability:** < 1% flaky test rate
- **Code Coverage:** Maintain 80%+ overall coverage
- **Test Maintenance:** Tests updated with code changes

---

## Resource Requirements

### Team
- **Backend Developer:** 1 FTE for 22 weeks
- **Frontend Developer:** 0.5 FTE for 4 weeks (Weeks 17-20)
- **QA Engineer:** 0.25 FTE for review and validation

### Tools & Infrastructure
- Test database (PostgreSQL test container)
- CI/CD infrastructure (GitHub Actions)
- Test reporting tools (Codecov, etc.)
- Frontend testing tools (Vitest, Playwright)

### Estimated Effort
- **Total:** ~26 developer-weeks
- **Timeline:** 22 weeks (5.5 months)
- **Parallel work:** Frontend testing can run parallel to backend E2E expansion

---

## Risk Mitigation

### Risks

1. **Time Constraints**
   - **Mitigation:** Prioritize critical services first, defer non-critical tests
   - **Fallback:** Extend timeline or reduce scope

2. **Test Maintenance Burden**
   - **Mitigation:** Establish clear testing standards, use test utilities
   - **Fallback:** Focus on high-value tests, reduce coverage targets

3. **Flaky Tests**
   - **Mitigation:** Use proper mocking, avoid time-dependent tests
   - **Fallback:** Retry logic, test isolation improvements

4. **Integration Test Complexity**
   - **Mitigation:** Use test containers, proper test data management
   - **Fallback:** Mock external dependencies, reduce integration scope

---

## Implementation Guidelines

### Unit Test Standards

**Structure:**
```typescript
describe('ServiceName', () => {
  let service: ServiceName;
  let mockDependency: jest.Mocked<Dependency>;

  beforeEach(async () => {
    // Setup
  });

  describe('methodName', () => {
    it('should [expected behavior] when [condition]', async () => {
      // Arrange
      // Act
      // Assert
    });

    it('should throw [Exception] when [error condition]', async () => {
      // Test error case
    });
  });
});
```

**Coverage Requirements:**
- Success cases
- Validation errors
- Service errors
- Edge cases
- Boundary conditions

### Integration Test Standards

**Structure:**
```typescript
describe('Workflow Name (Integration)', () => {
  let app: INestApplication;
  let testDb: TestDatabase;

  beforeAll(async () => {
    // Setup test environment
  });

  it('should complete workflow end-to-end', async () => {
    // Test multi-service workflow
  });
});
```

### E2E Test Standards

**Structure:**
```typescript
describe('Feature Name (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  describe('POST /api/endpoint', () => {
    it('should return 200 with valid input', () => {
      return request(app.getHttpServer())
        .post('/api/endpoint')
        .send(validPayload)
        .expect(200)
        .expect((res) => {
          expect(res.body).toHaveProperty('expectedField');
        });
    });
  });
});
```

### Frontend Test Standards

**Component Test:**
```typescript
import { mount } from '@vue/test-utils';
import Component from './Component.vue';

describe('Component', () => {
  it('renders correctly', () => {
    const wrapper = mount(Component, {
      props: { /* props */ }
    });
    expect(wrapper.text()).toContain('expected text');
  });
});
```

**E2E Test:**
```typescript
import { test, expect } from '@playwright/test';

test('user can create test', async ({ page }) => {
  await page.goto('/tests/create');
  await page.fill('[name="testName"]', 'My Test');
  await page.click('button[type="submit"]');
  await expect(page.locator('.success-message')).toBeVisible();
});
```

---

## Next Steps

1. **Review & Approve Plan** (Week 1)
   - Review with team
   - Adjust priorities if needed
   - Get stakeholder approval

2. **Set Up Infrastructure** (Week 1-2)
   - Configure test infrastructure
   - Set up frontend testing tools
   - Create test utilities

3. **Begin Implementation** (Week 3)
   - Start with Phase 2 (Unit Test Expansion)
   - Follow priority order
   - Track progress weekly

4. **Monitor & Adjust** (Ongoing)
   - Weekly progress reviews
   - Adjust timeline as needed
   - Address blockers promptly

---

## Appendix

### A. Service Priority Matrix

**Critical (P0):**
- Auth, Policies, Tests, Applications, Compliance

**High (P1):**
- Test Suites, Test Harnesses, Test Batteries, Users, Violations

**Medium (P2):**
- All other services

### B. Test File Naming Conventions

- Unit tests: `*.service.spec.ts`, `*.controller.spec.ts`
- Integration tests: `*.integration.spec.ts`
- E2E tests: `*.e2e-spec.ts`
- Frontend component tests: `*.spec.ts`
- Frontend E2E tests: `*.e2e.spec.ts`

### C. Coverage Exclusions

**Exclude from coverage:**
- Migration files
- Configuration files
- Type definitions
- Test utilities
- Main entry points (minimal logic)

### D. References

- [Testing Guide](./dashboard-api/docs/api/TESTING.md)
- [Test Creation Guide](./docs/guides/TEST_CREATION_GUIDE.md)
- Jest Documentation: https://jestjs.io/
- Vitest Documentation: https://vitest.dev/
- Playwright Documentation: https://playwright.dev/
