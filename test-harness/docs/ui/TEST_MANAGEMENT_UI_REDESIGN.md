# Refocus Test Management UI for Viewing and Management

## Core Purpose Clarification

**The UI is NOT for running tests** - Tests execute automatically in CI/CD during builds.

**The UI IS for**:
- Viewing tests, test suites, and configurations
- Reviewing findings from test runs
- Reporting and analytics
- Risk acceptance workflows
- Identifying what tests run on which applications
- Managing test organization (Test Harnesses → Test Suites → Configurations)

## New Hierarchy

```
Test Harness (NEW - Global, assigned to applications)
  └── Test Suites (many-to-many: one suite can be in multiple harnesses)
      └── Configurations (test parameters)
          └── Individual Tests (test functions)
```

**Relationships**:
- Test Harness: Global entity, assigned to applications
- Test Suite: Can belong to multiple Test Harnesses (many-to-many)
- Application: Has Test Harnesses assigned to it
- Test Harness: Contains Test Suites, runs against assigned Applications

## Navigation Structure

### Top-Level Navigation Items:
1. **Dashboard** (`/dashboard` or `/`) - Overview, stats, recent findings, quick links
2. **Applications** (`/applications`) - View applications and their assigned test harnesses
3. **Tests** (`/tests`) - Test management (harnesses, suites, library, findings)
4. **Reports** (`/reports`) - Generate and view reports

### Tests Page Tabs:
1. **Test Harnesses** - View and manage test harnesses (collections of suites)
2. **Test Suites** - View and manage test suites (filterable by harness)
3. **Test Library** - Browse available test types and configurations
4. **Findings** - Review test results, violations, risk acceptance

## Proposed Structure

### Phase 1: Add Test Harness Concept
**Goal**: Introduce Test Harness as a collection of Test Suites

**Changes**:
- Add "Test Harnesses" as top-level entity
- Test Harness contains multiple Test Suites (many-to-many relationship)
- Test Harness is global but assigned to applications
- UI shows: Harnesses → Suites → Configurations hierarchy

**Tests Page Tab Structure**:
1. **Test Harnesses** - View and manage test harnesses (collections of suites)
2. **Test Suites** - View and manage test suites (filterable by harness)
3. **Test Library** - Browse available test types and configurations
4. **Findings** - Review test results, violations, risk acceptance

### Phase 2: Remove Test Execution UI
**Goal**: Remove all "Run Test" functionality from UI

**Changes**:
- Remove "Run Test" buttons from TestTypeCard
- Remove "Execution" tab
- Remove test execution modals
- Keep only viewing/configuration capabilities
- Add note: "Tests run automatically in CI/CD during builds"

### Phase 3: Dashboard Page (Separate Navigation Item)
**Goal**: Provide overview and quick access to key information

**Dashboard Page** (`/dashboard` or `/`):
- Overall compliance metrics
- Applications at risk
- Recent findings summary
- Test coverage by application
- Trend charts
- Test harness status overview
- Quick actions:
  - View applications
  - View test harnesses
  - View recent findings
  - Generate reports

### Phase 4: Applications Page (Separate Navigation Item)
**Goal**: Show which applications have which test harnesses assigned

**Applications Page** (`/applications`):
- List of all applications
- For each application, show:
  - Assigned test harnesses
  - Test suites that will run (from harnesses)
  - Last test run status (from CI/CD)
  - Current findings count
  - Compliance score
  - Quick actions: View harnesses, View findings, View reports
- Actions:
  - Assign/remove test harnesses to applications
  - View application details
  - View test configuration for application
  - Navigate to related test harnesses/suites

### Phase 5: Test Harness Management
**Goal**: Make it easy to create and manage test harnesses

**Test Harness View** (in Tests page):
- List of all test harnesses (global)
- Each harness shows:
  - Name and description
  - Test suites in the harness
  - Applications it's assigned to
  - Last run status (aggregated from applications)
  - Overall health/status
- Actions:
  - Create new harness
  - Edit harness (add/remove test suites)
  - Assign to applications (links to Applications page)
  - View details
  - View results across all assigned applications

**Test Harness Detail View**:
- Harness information
- List of test suites (with ability to add/remove)
- List of assigned applications (with links to Applications page)
- Test configuration summary
- Recent run results (from all assigned applications)

### Phase 6: Focus on Viewing and Discovery
**Goal**: Make it easy to understand what tests exist and how they're organized

**Test Suite View** (in Tests page):
- List of test suites (filterable by harness, application)
- Each suite shows:
  - Which harness(es) it belongs to
  - Configurations used
  - Applications it runs against (via harnesses)
  - Last run results
- Actions: View details, Edit, View results

**Test Library View** (in Tests page):
- Browse available test types
- View available configurations for each type
- See which suites/configs use each test type
- See which applications run each test type (via harnesses)
- NO run buttons - just viewing and configuration

### Phase 7: Enhance Findings/Results View
**Goal**: Make it easy to review test results and manage risk

**Findings Tab** (in Tests page):
- List of findings from CI/CD test runs
- Filter by:
  - Application
  - Test harness
  - Test suite
  - Severity
  - Status (new, accepted, remediated)
  - Date range
- Risk acceptance workflow:
  - View finding details
  - Accept risk (with reason/approval)
  - Link to remediation tickets
  - Track remediation status

**Results View**:
- Timeline of test runs (from CI/CD)
- Filter by application, harness, suite
- Compare runs over time
- View detailed test results
- Link to related findings

### Phase 8: Reports Page (Separate Navigation Item)
**Goal**: Provide insights and reporting capabilities

**Reports Page** (`/reports`):
- Generate compliance reports
- Application health reports
- Test coverage reports
- Trend analysis
- Export capabilities
- Scheduled reports

## Implementation Details

### Test Harness Entity
```typescript
interface TestHarness {
  id: string;
  name: string;
  description: string;
  testSuiteIds: string[]; // Many test suites
  applicationIds: string[]; // Assigned to applications
  team?: string;
  createdAt: Date;
  updatedAt: Date;
}
```

### Updated Navigation Structure
```
Top-Level Navigation:
├── Dashboard (/dashboard) - Overview, stats, quick access
├── Applications (/applications) - View apps and their test harnesses
├── Tests (/tests) - Test management
│   ├── Test Harnesses - Manage test harnesses
│   ├── Test Suites - View and manage test suites
│   ├── Test Library - Browse test types and configurations
│   └── Findings - Review results and risk acceptance
└── Reports (/reports) - Generate reports
```

### UI Changes Summary
1. **Add**: Test Harnesses tab in Tests page, Dashboard as separate page, Applications as separate page, Reports as separate page
2. **Remove**: Execution tab, all "Run Test" buttons, test execution modals, Dashboard tab from Tests page
3. **Update**: TestTypeCard to remove execution, focus on viewing
4. **Update**: Tests page to remove Dashboard tab (it's now separate)
5. **Update**: Test Suites to show which harnesses they belong to
6. **Enhance**: Findings with risk acceptance workflows
7. **Create**: Applications page showing test harness assignments
8. **Enhance**: Reports page with test-related reporting

## Key Relationships to Display

1. **Application → Test Harnesses**: Which harnesses are assigned (shown in Applications page)
2. **Test Harness → Test Suites**: Which suites are in the harness (shown in Tests page)
3. **Test Suite → Test Harnesses**: Which harnesses contain this suite (many-to-many, shown in Tests page)
4. **Test Suite → Configurations**: Which configs are used (shown in Tests page)
5. **Application → Test Runs**: Results from CI/CD (shown in Applications and Findings)
6. **Test Run → Findings**: Issues discovered (shown in Findings tab)

