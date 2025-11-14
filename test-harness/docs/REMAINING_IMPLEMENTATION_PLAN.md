# Remaining Implementation Plan - Test Management UI Redesign

## Overview

This document outlines the remaining work needed to complete the Test Management UI Redesign and Test Battery implementation. The foundation is in place (backend APIs, basic UI structure), but several key features need to be implemented.

## Current Status

### ✅ Completed Foundation
- Backend APIs for Test Harnesses and Test Batteries (full CRUD)
- Test Battery Runner class
- Basic frontend structure (tabs, routes, list views)
- Terminology resolved (Sentinel → TestOrchestrator)
- Execution UI removed from Tests page

### ⚠️ Partially Complete
- Applications page (basic view, missing assignment management)
- Test Suites view (needs harness relationship display)
- Findings tab (needs enhanced filtering and risk acceptance)

### ❌ Not Started
- Create/Edit modals for batteries and harnesses
- Detail views for batteries and harnesses
- Assignment management UI
- Risk acceptance workflow
- Dashboard enhancements
- TestTypeCard "Run" button removal

---

## Implementation Plan

### Priority 1: Critical UI Components

#### 1.1 Remove "Run" Buttons from TestTypeCard
**File**: `dashboard-frontend/src/components/TestTypeCard.vue`

**Changes Needed**:
- Remove `runTest()` function
- Remove `runTestFunction()` function
- Remove "Run" buttons from test function cards
- Remove configuration selector if only used for running tests
- Add info message: "Tests run automatically in CI/CD during builds"
- Keep viewing and configuration capabilities only

**Estimated Effort**: 30 minutes

---

#### 1.2 Create Test Battery Modal Component
**File**: `dashboard-frontend/src/components/TestBatteryModal.vue` (new)

**Functionality**:
- Create new test battery
- Edit existing test battery
- Form fields:
  - Name (required)
  - Description (optional)
  - Team (optional)
  - Execution Config:
    - Execution Mode (parallel/sequential) - dropdown
    - Timeout (optional number)
    - Stop on Failure (checkbox)
  - Harnesses selection (multi-select from available harnesses)

**API Integration**:
- POST `/api/test-batteries` for create
- PUT `/api/test-batteries/:id` for update
- GET `/api/test-harnesses` to populate harness selection

**Estimated Effort**: 2-3 hours

---

#### 1.3 Create Test Harness Modal Component
**File**: `dashboard-frontend/src/components/TestHarnessModal.vue` (new)

**Functionality**:
- Create new test harness
- Edit existing test harness
- Form fields:
  - Name (required)
  - Description (required)
  - Team (optional)
  - Test Suites selection (multi-select from available suites)
  - Applications selection (multi-select from available applications)

**API Integration**:
- POST `/api/test-harnesses` for create
- PUT `/api/test-harnesses/:id` for update
- GET `/api/test-suites` to populate suite selection
- GET `/api/applications` to populate application selection

**Estimated Effort**: 2-3 hours

---

#### 1.4 Create Test Battery Detail View
**File**: `dashboard-frontend/src/views/TestBatteryDetail.vue` (new)

**Route**: `/tests/batteries/:id`

**Functionality**:
- Display battery information (name, description, team, execution config)
- List of harnesses in the battery (with ability to add/remove)
- Recent execution results (if available)
- Actions:
  - Edit battery
  - Delete battery
  - Add harness to battery
  - Remove harness from battery
  - View harness details (link)

**API Integration**:
- GET `/api/test-batteries/:id`
- GET `/api/test-harnesses` (filtered by battery)
- POST `/api/test-batteries/:id/harnesses`
- DELETE `/api/test-batteries/:id/harnesses/:harnessId`

**Estimated Effort**: 3-4 hours

---

#### 1.5 Create Test Harness Detail View
**File**: `dashboard-frontend/src/views/TestHarnessDetail.vue` (new)

**Route**: `/tests/harnesses/:id`

**Functionality**:
- Display harness information (name, description, team)
- List of test suites in the harness (with ability to add/remove)
- List of assigned applications (with ability to assign/unassign)
- Test configuration summary
- Recent run results (from all assigned applications)
- Actions:
  - Edit harness
  - Delete harness
  - Add suite to harness
  - Remove suite from harness
  - Assign to application
  - Unassign from application
  - View suite details (link)
  - View application details (link)

**API Integration**:
- GET `/api/test-harnesses/:id`
- GET `/api/test-suites` (filtered by harness)
- GET `/api/applications` (filtered by harness)
- POST `/api/test-harnesses/:id/test-suites`
- DELETE `/api/test-harnesses/:id/test-suites/:suiteId`
- POST `/api/test-harnesses/:id/applications`
- DELETE `/api/test-harnesses/:id/applications/:appId`

**Estimated Effort**: 4-5 hours

---

### Priority 2: Relationship Display and Management

#### 2.1 Update Test Suites View to Show Harness Relationships
**File**: `dashboard-frontend/src/views/Tests.vue`

**Changes Needed**:
- Add "Harnesses" column/badge to test suite cards showing which harness(es) contain the suite
- Add filter dropdown: "Filter by Harness"
- Update `loadTestSuites()` to also fetch harness relationships
- Display harness names as clickable badges that navigate to harness detail view

**Backend Support Needed**:
- Update Test Suites service to return `harnessIds` for each suite
- Or add endpoint: GET `/api/test-suites/:id/harnesses`

**Estimated Effort**: 2-3 hours

---

#### 2.2 Update Test Suites Service for Relationship Tracking
**File**: `dashboard-api/src/test-suites/test-suites.service.ts`

**Changes Needed**:
- When loading suites, also query test harnesses to find which harnesses contain each suite
- Add `harnessIds` field to TestSuiteEntity (or compute on-the-fly)
- Add method: `findHarnessesForSuite(suiteId: string): Promise<TestHarnessEntity[]>`

**Alternative Approach**:
- Add endpoint: GET `/api/test-harnesses?suiteId=:suiteId` (already exists)
- Frontend can call this to get harnesses for each suite

**Estimated Effort**: 1-2 hours

---

#### 2.3 Update Applications Service for Assignment Tracking
**File**: `dashboard-api/src/applications/applications.service.ts`

**Changes Needed**:
- Add methods to get assigned test harnesses and batteries for an application
- Add methods to assign/unassign harnesses and batteries
- Update application entity to include `testHarnessIds` and `testBatteryIds` (or compute on-the-fly)

**API Endpoints Needed**:
- GET `/api/applications/:id/test-harnesses`
- GET `/api/applications/:id/test-batteries`
- POST `/api/applications/:id/test-harnesses`
- DELETE `/api/applications/:id/test-harnesses/:harnessId`
- POST `/api/applications/:id/test-batteries`
- DELETE `/api/applications/:id/test-batteries/:batteryId`

**Estimated Effort**: 2-3 hours

---

### Priority 3: Assignment Management UI

#### 3.1 Create Assignment Manager Component
**File**: `dashboard-frontend/src/components/AssignmentManager.vue` (new)

**Functionality**:
- Modal/drawer component for managing assignments
- Two sections:
  1. **Test Harnesses**: List available harnesses with checkboxes, show assigned ones
  2. **Test Batteries**: List available batteries with checkboxes, show assigned ones
- Save button to persist changes
- Cancel button to close without saving

**Usage**:
- Used from Applications page "Manage Assignments" button
- Can also be used from Harness/Battery detail views

**API Integration**:
- GET `/api/test-harnesses` to list all harnesses
- GET `/api/test-batteries` to list all batteries
- POST/DELETE endpoints for assignments (see 2.3)

**Estimated Effort**: 3-4 hours

---

#### 3.2 Enhance Applications Page
**File**: `dashboard-frontend/src/views/Applications.vue`

**Changes Needed**:
- Implement `manageAssignments()` function to open AssignmentManager modal
- Add "Assign Harnesses" and "Assign Batteries" quick action buttons
- Show last test run status (needs backend support for CI/CD integration)
- Add navigation links to harness/battery detail views
- Add filter/search functionality

**Estimated Effort**: 2-3 hours

---

### Priority 4: Findings Tab Enhancements

#### 4.1 Add Enhanced Filtering to Findings Tab
**File**: `dashboard-frontend/src/views/Tests.vue` (Findings tab section)

**Changes Needed**:
- Add filter dropdowns:
  - Application (already exists via suite filter, but add direct filter)
  - Test Battery (new)
  - Test Harness (new)
  - Severity (new)
  - Status: new, accepted, remediated (new)
  - Date range picker (new)
- Update `filteredResults` computed to include new filters

**Backend Support Needed**:
- Update test results endpoint to support filtering by battery/harness
- Or filter client-side after fetching all results

**Estimated Effort**: 2-3 hours

---

#### 4.2 Add Risk Acceptance Workflow
**File**: `dashboard-frontend/src/components/RiskAcceptanceModal.vue` (new)

**Functionality**:
- Modal for accepting risk on a finding
- Form fields:
  - Reason for acceptance (required textarea)
  - Approval required (checkbox, if needed)
  - Expiration date (optional)
  - Link to remediation ticket (optional URL)
- Save button to persist acceptance
- Display accepted findings with different styling

**Backend Support Needed**:
- Add risk acceptance fields to test results/findings entity
- Add endpoint: POST `/api/test-results/:id/accept-risk`
- Add endpoint: GET `/api/test-results?status=accepted`
- Store acceptance metadata (reason, approver, date, expiration)

**Estimated Effort**: 4-5 hours

---

#### 4.3 Add Remediation Tracking
**File**: `dashboard-frontend/src/components/RemediationTracker.vue` (new)

**Functionality**:
- Component to track remediation status
- Fields:
  - Status: new, in-progress, remediated, accepted
  - Remediation ticket link (Jira, ServiceNow, etc.)
  - Assigned to (user/team)
  - Target completion date
  - Notes
- Display in Findings tab with status badges
- Filter by remediation status

**Backend Support Needed**:
- Add remediation tracking fields to findings entity
- Add endpoints for updating remediation status
- Integration with ticketing systems (if not already done)

**Estimated Effort**: 3-4 hours

---

#### 4.4 Add Timeline View for Test Runs
**File**: `dashboard-frontend/src/components/TestRunTimeline.vue` (new)

**Functionality**:
- Timeline visualization of test runs
- Filter by application, harness, suite, date range
- Show pass/fail status for each run
- Click to view detailed results
- Compare runs over time (trend visualization)

**Backend Support Needed**:
- Endpoint to get test run history: GET `/api/test-results/history`
- Support filtering and date range queries

**Estimated Effort**: 4-5 hours

---

### Priority 5: Dashboard Enhancements

#### 5.1 Add Test Battery Status Overview
**File**: `dashboard-frontend/src/views/Dashboard.vue`

**Changes Needed**:
- Add section: "Test Batteries Status"
- Show:
  - Total batteries count
  - Batteries by status (healthy, warning, error)
  - Recent battery executions
  - Quick links to view batteries
- Add quick action: "View Test Batteries"

**Estimated Effort**: 2-3 hours

---

#### 5.2 Add Test Harness Status Overview
**File**: `dashboard-frontend/src/views/Dashboard.vue`

**Changes Needed**:
- Add section: "Test Harnesses Status"
- Show:
  - Total harnesses count
  - Harnesses by status
  - Applications coverage (how many apps have harnesses assigned)
  - Quick links to view harnesses
- Add quick action: "View Test Harnesses"

**Estimated Effort**: 2-3 hours

---

#### 5.3 Add Quick Actions to Dashboard
**File**: `dashboard-frontend/src/views/Dashboard.vue`

**Changes Needed**:
- Add quick actions section with buttons:
  - View Applications
  - View Test Batteries
  - View Test Harnesses
  - View Recent Findings
  - Generate Report
- Style consistently with existing quick actions

**Estimated Effort**: 1 hour

---

### Priority 6: Test Library Enhancements

#### 6.1 Show Suite/Config Usage in Test Library
**File**: `dashboard-frontend/src/views/Tests.vue` (Test Library tab)

**Changes Needed**:
- For each test type, show:
  - Which test suites use this type
  - Which configurations exist for this type
  - Which applications run this type (via harnesses)
- Add expandable sections or tooltips to show this information
- Make it clear this is for viewing only (no run buttons)

**Backend Support Needed**:
- May need to aggregate data from multiple sources
- Or compute on frontend from existing data

**Estimated Effort**: 2-3 hours

---

### Priority 7: Backend Enhancements

#### 7.1 Add Test Results Filtering by Harness/Battery
**File**: `dashboard-api/src/test-results/test-results.service.ts`

**Changes Needed**:
- Add query parameters to filter results by:
  - Test harness ID
  - Test battery ID
  - Application ID
- Update controller to accept these filters
- Update service methods to apply filters

**Estimated Effort**: 1-2 hours

---

#### 7.2 Add Risk Acceptance Endpoints
**File**: `dashboard-api/src/test-results/test-results.controller.ts` and `test-results.service.ts`

**Changes Needed**:
- Add endpoint: POST `/api/test-results/:id/accept-risk`
  - Body: { reason, approver, expirationDate?, ticketLink? }
- Add endpoint: POST `/api/test-results/:id/reject-risk` (undo acceptance)
- Update TestResult entity to include risk acceptance fields
- Store acceptance metadata in data file

**Estimated Effort**: 2-3 hours

---

#### 7.3 Add Remediation Tracking Endpoints
**File**: `dashboard-api/src/test-results/test-results.controller.ts` and `test-results.service.ts`

**Changes Needed**:
- Add endpoint: PUT `/api/test-results/:id/remediation`
  - Body: { status, ticketLink, assignedTo, targetDate, notes }
- Update TestResult entity to include remediation fields
- Store remediation metadata in data file

**Estimated Effort**: 2-3 hours

---

### Priority 8: Documentation Updates

#### 8.1 Update API Documentation
**File**: `docs/API.md`

**Changes Needed**:
- Document all new Test Harness endpoints
- Document all new Test Battery endpoints
- Document risk acceptance endpoints
- Document remediation tracking endpoints
- Add request/response examples

**Estimated Effort**: 2-3 hours

---

#### 8.2 Update User Guide
**File**: `docs/USER_GUIDE.md`

**Changes Needed**:
- Add section on Test Batteries
- Add section on Test Harnesses
- Update navigation structure documentation
- Add examples of creating batteries and harnesses
- Document assignment workflow
- Document risk acceptance workflow

**Estimated Effort**: 2-3 hours

---

#### 8.3 Create Test Battery Usage Example
**File**: `examples/test-battery-usage.ts` (new)

**Content**:
- Example of creating a test battery
- Example of running a test battery
- Example of managing harnesses in a battery

**Estimated Effort**: 1 hour

---

### Priority 9: Reports Page Enhancements

#### 9.1 Add Test Battery Coverage Reports
**File**: `dashboard-frontend/src/views/Reports.vue`

**Changes Needed**:
- Add report type: "Test Battery Coverage"
- Show coverage by battery (which harnesses, suites, applications)
- Show execution status per battery
- Include battery execution history
- Display battery health metrics

**Backend Support Needed**:
- May need to aggregate data from battery executions
- Or compute on frontend from existing data

**Estimated Effort**: 2-3 hours

---

#### 9.2 Add Test Harness Coverage Reports
**File**: `dashboard-frontend/src/views/Reports.vue`

**Changes Needed**:
- Add report type: "Test Harness Coverage"
- Show coverage by harness (which suites, applications)
- Show execution status per harness
- Include harness execution history
- Display harness health metrics

**Backend Support Needed**:
- May need to aggregate data from harness executions
- Or compute on frontend from existing data

**Estimated Effort**: 2-3 hours

---

#### 9.3 Add Filtering by Battery/Harness in Report Generation
**File**: `dashboard-frontend/src/views/Reports.vue`

**Changes Needed**:
- Add filter dropdowns for Test Battery and Test Harness in report generation modal
- Allow generating reports for specific batteries/harnesses
- Update report generation API to accept battery/harness filters
- Show filtered results in generated reports

**Backend Support Needed**:
- Update report generation endpoint to filter by battery/harness
- Aggregate data from battery/harness executions
- Include battery/harness metadata in report data

**Estimated Effort**: 2-3 hours

---

#### 9.4 Add Battery/Harness Execution Reports
**File**: `dashboard-frontend/src/views/Reports.vue`

**Changes Needed**:
- Add report type: "Battery Execution Report"
- Add report type: "Harness Execution Report"
- Show execution results, pass/fail rates, trends
- Include timing and performance metrics
- Show execution history over time
- Compare executions across batteries/harnesses

**Backend Support Needed**:
- Endpoint to get battery/harness execution history
- Aggregate execution metrics
- Support date range filtering

**Estimated Effort**: 3-4 hours

---

## Implementation Order Recommendation

### Phase 1: Critical UI Components (Week 1)
1. Remove "Run" buttons from TestTypeCard
2. Create Test Battery Modal
3. Create Test Harness Modal
4. Create Test Battery Detail View
5. Create Test Harness Detail View

### Phase 2: Relationship Management (Week 1-2)
6. Update Test Suites view to show harness relationships
7. Update Test Suites service for relationship tracking
8. Update Applications service for assignment tracking
9. Create Assignment Manager component
10. Enhance Applications page

### Phase 3: Findings Enhancements (Week 2)
11. Add enhanced filtering to Findings tab
12. Add Risk Acceptance workflow
13. Add Remediation Tracking
14. Add Timeline view for test runs

### Phase 4: Dashboard and Polish (Week 2-3)
15. Add Test Battery status to Dashboard
16. Add Test Harness status to Dashboard
17. Add Quick Actions to Dashboard
18. Show suite/config usage in Test Library

### Phase 5: Backend Enhancements (Week 3)
19. Add test results filtering by harness/battery
20. Add risk acceptance endpoints
21. Add remediation tracking endpoints

### Phase 6: Reports Enhancements (Week 3)
22. Add Test Battery coverage reports
23. Add Test Harness coverage reports
24. Add filtering by battery/harness in report generation
25. Add Battery/Harness execution reports

### Phase 7: Documentation (Week 3-4)
26. Update API documentation
27. Update User Guide
28. Create Test Battery usage example

---

## Estimated Total Effort

- **Phase 1**: ~12-16 hours
- **Phase 2**: ~10-14 hours
- **Phase 3**: ~13-17 hours
- **Phase 4**: ~7-10 hours
- **Phase 5**: ~5-8 hours
- **Phase 6**: ~9-13 hours
- **Phase 7**: ~5-7 hours

**Total**: ~61-85 hours (approximately 2-2.5 weeks of focused development)

---

## Dependencies and Blockers

### No Blockers
All remaining work can proceed independently. The backend APIs are ready, and the frontend structure is in place.

### Recommended Sequence
1. Start with removing "Run" buttons (quick win)
2. Create modals before detail views (modals are simpler)
3. Implement assignment management after modals (needs modals)
4. Enhance findings after core functionality (depends on data structure)
5. Polish dashboard last (depends on other features being complete)

---

## Testing Considerations

### Unit Tests Needed
- Test Battery service methods
- Test Harness service methods
- Test Battery Runner execution logic
- Risk acceptance workflow
- Remediation tracking

### Integration Tests Needed
- Test Battery CRUD operations
- Test Harness CRUD operations
- Assignment management workflows
- Filtering and querying

### E2E Tests Needed
- Create battery → add harnesses → view details
- Create harness → add suites → assign to application
- Accept risk on finding → verify status update
- Filter findings by harness/battery

---

## Notes

- All backend APIs are functional and ready to use
- Frontend structure is in place, mostly needs content/completion
- No breaking changes expected
- Can be implemented incrementally
- Each phase can be tested independently

