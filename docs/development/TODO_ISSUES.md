# TODO Items - Issues to Create

This document lists remaining TODO comments in the codebase that should be converted to GitHub issues for tracking.

## ✅ Completed TODOs

### Auth Context Integration
- **Fixed**: All instances of `// TODO: Get from auth context` have been resolved
  - `Violations.vue` - Now uses `useAuth().user.value.email`
  - `ViolationDetailModal.vue` - Now uses `useAuth().user.value.email`
  - `EvidenceManager.vue` - Now uses `useAuth().user.value.email`

## 🔴 High Priority - Backend API Integration

### 1. Settings API Implementation
**Location**: `dashboard-frontend/src/views/Settings.vue`
**TODOs**:
- Line 666: `// TODO: Load settings from API when backend is ready`
- Line 675: `// TODO: Save settings to API when backend is ready`
- Line 735: `// TODO: Send test email via API when backend is ready`
- Line 744: `// TODO: Send test Slack message via API when backend is ready`

**Description**: The Settings page has UI for managing application settings, notifications, and security settings, but the backend API endpoints are not yet implemented.

**Recommended Issue**:
- **Title**: Implement Settings API endpoints
- **Description**: 
  - Create `/api/v1/settings` GET endpoint to load settings
  - Create `/api/v1/settings` POST/PUT endpoint to save settings
  - Create `/api/v1/settings/test-email` POST endpoint for testing email configuration
  - Create `/api/v1/settings/test-slack` POST endpoint for testing Slack integration
  - Settings should include: general settings (app name, timezone, date format, etc.), notification settings (SMTP, Slack, webhooks), and security settings (session timeout, 2FA, password policy, etc.)

### 2. Platform Config Validation Stats API
**Location**: `dashboard-frontend/src/views/PlatformConfigOverview.vue`
**TODO**: Line 163: `// TODO: Load validation stats from API when backend is ready`

**Description**: The Platform Config Overview page needs to display validation statistics, but the API endpoint is not yet implemented.

**Recommended Issue**:
- **Title**: Implement Platform Config validation stats API
- **Description**: Create `/api/v1/platform-config/stats` or similar endpoint to return validation statistics for platform configurations (baselines, validators, etc.)

## 🟡 Medium Priority - UI Features

### 3. Infrastructure Edit Modal
**Location**: `dashboard-frontend/src/views/ApplicationDetail.vue`
**TODO**: Line 783: `// TODO: Open infrastructure edit modal`

**Description**: Currently shows an alert when trying to edit infrastructure. Should open a modal for editing infrastructure configuration.

**Recommended Issue**:
- **Title**: Implement Infrastructure Edit Modal
- **Description**: 
  - Create a modal component for editing application infrastructure configuration
  - Replace the alert with modal functionality
  - Modal should allow editing: databases, API gateways, DLP configs, network segments, distributed systems, data pipelines, etc.
  - Use existing infrastructure configuration forms/components where possible

## 🟢 Low Priority - Feature Enhancements

### 4. Normalization Engine Adapters
**Location**: `services/normalization-engine.ts`
**TODO**: Line 107: `// TODO: Add more adapters as needed (Veracode, Checkmarx, Burp Suite, etc.)`

**Description**: The normalization engine currently supports several scanner adapters. Additional adapters can be added as needed.

**Recommended Issue**:
- **Title**: Add additional scanner adapters to normalization engine
- **Description**: 
  - Add adapters for Veracode, Checkmarx, Burp Suite, and other security scanners
  - Follow the existing adapter pattern (extend `BaseScannerAdapter`)
  - Ensure proper normalization to unified finding schema

### 5. CVE/CWE Enrichment API Integration
**Location**: `services/normalization-engine.ts`
**TODOs**: 
- Line 206: `// TODO: Fetch CVE details from external API`
- Line 212: `// TODO: Fetch CWE details from external API`

**Description**: The normalization engine has placeholder code for enriching findings with CVE and CWE details from external APIs.

**Recommended Issue**:
- **Title**: Integrate CVE/CWE enrichment APIs
- **Description**: 
  - Integrate with CVE database API (e.g., NVD API) to fetch CVE details
  - Integrate with CWE database to fetch CWE details
  - Cache results to avoid excessive API calls
  - Handle API rate limits and errors gracefully
  - Consider using libraries like `cve-search` or similar

## 📝 Notes

- All auth context TODOs have been resolved by using the existing `useAuth()` composable
- Settings API TODOs are high priority as they block full functionality of the Settings page
- Infrastructure edit modal is a UX improvement that would enhance the user experience
- Normalization engine enhancements are lower priority but would improve the system's capabilities

## 🧪 Test Coverage Expansion

### Test Coverage Expansion Plan
**Status**: Plan created, ready for implementation  
**Documentation**: See [TEST_COVERAGE_EXPANSION_PLAN.md](./TEST_COVERAGE_EXPANSION_PLAN.md) and [TEST_COVERAGE_QUICK_REFERENCE.md](./TEST_COVERAGE_QUICK_REFERENCE.md)

**Current State:**
- Unit Tests: 8/58 services (14% coverage)
- E2E Tests: 9 controller files
- Integration Tests: Limited
- Frontend Tests: None

**Target State:**
- Unit Tests: 80%+ coverage (46/58 services)
- E2E Tests: 20+ files covering all endpoints
- Integration Tests: 5+ major workflows
- Frontend Tests: 70%+ component coverage, 10+ E2E flows

**Timeline**: 22 weeks (5.5 months)

**Priority Actions:**
1. Set up test infrastructure and frontend testing tools (Weeks 1-2)
2. Expand unit tests for priority services (Weeks 3-4)
3. Add integration tests for critical workflows (Weeks 9-12)
4. Expand E2E tests for all endpoints (Weeks 13-16)
5. Add frontend component and E2E tests (Weeks 17-20)
6. Integrate tests into CI/CD with quality gates (Weeks 21-22)

## Summary

- **Total TODOs Found**: 12
- **Resolved**: 4 (all auth context TODOs)
- **Remaining**: 8
  - High Priority: 5 (Settings API + Platform Config Stats)
  - Medium Priority: 1 (Infrastructure Modal)
  - Low Priority: 2 (Normalization Engine enhancements)
- **Test Coverage**: Plan created - see TEST_COVERAGE_EXPANSION_PLAN.md
