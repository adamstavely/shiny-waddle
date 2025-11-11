# Sentinel Front-End UI Pages Requirements

Based on the comprehensive functionality of the Sentinel framework, here are all the UI pages that need to be created:

## Core Pages (Already Created - Need Implementation)

### 1. **Dashboard** (`/dashboard`)
**Status**: ✅ Created, ✅ Partially Implemented
**Needs**:
- Overall compliance score (✅ Done)
- Scores by application (✅ Done)
- Scores by team (✅ Done)
- Scores by category (✅ Done)
- Recent test results (✅ Done)
- **Missing**: Trends over time, compliance heatmap, quick actions

### 2. **Tests** (`/tests`)
**Status**: ✅ Created, ❌ Needs Full Implementation
**Required Features**:
- **Test Suites List**
  - View all test suites
  - Filter by application, team, status
  - Create new test suite
  - Edit/delete test suites
  - Run test suite
  - Test suite status (passing/failing/pending)
  
- **Test Suite Builder/Editor**
  - Configure test types (Access Control, Data Behavior, Contract, Dataset Health)
  - Define user roles and attributes
  - Configure resources and contexts
  - Define test queries
  - Set expected decisions
  - Configure allowed fields, required filters, disallowed joins
  - Contract definitions
  - Dataset configurations
  - Privacy thresholds
  - Statistical fidelity targets
  
- **Test Execution**
  - Run test suite interface
  - Real-time test execution progress
  - Test results viewer
  - Pass/fail indicators
  - Error details and stack traces
  
- **Test Results Detail**
  - Individual test result view
  - Test details breakdown
  - Comparison with previous runs
  - Export test results

### 3. **Reports** (`/reports`)
**Status**: ✅ Created, ❌ Needs Full Implementation
**Required Features**:
- **Reports List**
  - View all generated reports
  - Filter by date, application, team, type
  - Report status (generated, pending, failed)
  - Download reports (JSON, HTML, XML)
  
- **Report Viewer**
  - HTML report viewer
  - Report summary
  - Detailed test results
  - Compliance scores breakdown
  - Charts and visualizations
  - Export options
  
- **Report Generation**
  - Generate new report interface
  - Select test results to include
  - Choose report format
  - Schedule automated reports

### 4. **Policies** (`/policies`)
**Status**: ✅ Created, ❌ Needs Full Implementation
**Required Features**:
- **Policy List**
  - View all policies (RBAC and ABAC)
  - Filter by type, status, application
  - Policy status (active, draft, deprecated)
  - Create new policy
  - Edit/delete policies
  
- **Policy Editor**
  - RBAC policy editor
  - ABAC policy editor
  - Policy rule builder (visual/form-based)
  - Condition editor with operators
  - Policy validation
  - Policy testing interface
  - Policy preview
  
- **Policy Management**
  - Policy versioning
  - Policy comparison (diff view)
  - Policy deployment
  - Policy rollback
  - Policy audit log

### 5. **Analytics** (`/analytics`)
**Status**: ✅ Created, ❌ Needs Full Implementation
**Required Features**:
- **Compliance Trends**
  - Compliance score over time (line charts)
  - Trends by application
  - Trends by team
  - Trends by category
  
- **Score Analytics**
  - Score distribution charts
  - Score breakdown by test type
  - Score comparison across applications/teams
  
- **Violation Patterns**
  - Most common violations
  - Violation frequency charts
  - Violation trends
  - Violation correlation analysis
  
- **Performance Metrics**
  - Test execution time trends
  - Test suite performance
  - Resource usage metrics

### 6. **Violations** (`/violations`)
**Status**: ✅ Created, ❌ Needs Full Implementation
**Required Features**:
- **Violations List**
  - View all violations
  - Filter by severity, type, application, team, status
  - Sort by date, severity, application
  - Violation status (open, in-progress, resolved, ignored)
  
- **Violation Details**
  - Violation description
  - Affected resources
  - Test results that triggered violation
  - Policy that was violated
  - Remediation suggestions
  
- **Violation Management**
  - Assign violations
  - Add comments/notes
  - Mark as resolved
  - Ignore violations
  - Link to related violations
  
- **Remediation Tracking**
  - Remediation status
  - Remediation timeline
  - Verification tests

### 7. **History** (`/history`)
**Status**: ✅ Created, ❌ Needs Full Implementation
**Required Features**:
- **Test Execution History**
  - Timeline view of all test executions
  - Filter by date range, application, team, status
  - Test execution details
  - Compare executions
  
- **Audit Logs**
  - User actions log
  - Policy changes log
  - Test suite changes log
  - System events log
  - Filter and search capabilities
  
- **Activity Feed**
  - Recent activities
  - Test runs
  - Policy updates
  - Report generations
  - Violation resolutions

## Additional Pages Needed

### 8. **Test Suite Builder** (`/tests/builder` or `/tests/new`)
**Status**: ❌ Not Created
**Required Features**:
- Step-by-step test suite creation wizard
- Test type selection
- Configuration forms for each test type
- Preview and validation
- Save as draft or publish

### 9. **User Simulation** (`/users` or `/simulation`)
**Status**: ❌ Not Created
**Required Features**:
- **User Roles Management**
  - View all user roles
  - Create/edit/delete roles
  - Role permissions configuration
  
- **User Attributes Management**
  - ABAC attributes configuration
  - Attribute templates
  - Attribute validation rules
  
- **User Simulation**
  - Generate test users
  - Preview simulated users
  - Export user configurations

### 10. **Resources** (`/resources`)
**Status**: ❌ Not Created
**Required Features**:
- **Resource List**
  - View all resources
  - Filter by type, sensitivity, application
  - Create/edit/delete resources
  
- **Resource Management**
  - Resource attributes configuration
  - ABAC resource attributes
  - Resource sensitivity levels
  - Resource relationships

### 11. **Contracts** (`/contracts`)
**Status**: ❌ Not Created
**Required Features**:
- **Contract List**
  - View all data owner contracts
  - Filter by data owner, status
  - Create/edit/delete contracts
  
- **Contract Editor**
  - Contract requirements definition
  - Machine-readable contract builder
  - Contract validation
  - Contract testing interface
  
- **Contract Management**
  - Contract versioning
  - Contract approval workflow
  - Contract compliance tracking

### 12. **Datasets** (`/datasets`)
**Status**: ❌ Not Created
**Required Features**:
- **Dataset List**
  - View all datasets
  - Filter by type (raw, masked, synthetic)
  - Dataset health status
  
- **Dataset Management**
  - Dataset schema viewer
  - PII field identification
  - Privacy metrics configuration
  - Statistical fidelity targets
  
- **Dataset Health**
  - Privacy threshold monitoring
  - Statistical fidelity results
  - Health score visualization

### 13. **CI/CD Integration** (`/ci-cd` or `/integrations/ci-cd`)
**Status**: ❌ Not Created
**Required Features**:
- **CI/CD Configuration**
  - GitHub Actions workflow configuration
  - Compliance threshold settings
  - Merge blocking rules
  - Notification settings
  
- **CI/CD Status**
  - Recent CI/CD runs
  - PR compliance status
  - Blocked merges
  - CI/CD logs

### 14. **Ephemeral Environments** (`/environments` or `/ephemeral`)
**Status**: ❌ Not Created
**Required Features**:
- **Environment List**
  - View all ephemeral environments
  - Filter by PR, branch, status
  - Environment status (active, completed, failed)
  
- **Environment Management**
  - Create environment for PR
  - Environment details
  - Test results from environment
  - Environment cleanup
  
- **Environment Monitoring**
  - Environment health
  - Resource usage
  - Test execution status

### 15. **Integrations** (`/integrations`)
**Status**: ❌ Not Created
**Required Features**:
- **Integration List**
  - SAST integration
  - DAST integration
  - DBT integration
  - Great Expectations integration
  - Other integrations
  
- **Integration Configuration**
  - Configure each integration
  - Test integration connection
  - Integration status monitoring
  
- **Integration Results**
  - View results from each integration
  - Integration-specific dashboards

### 16. **API Security** (`/api-security` or `/tests/api-security`)
**Status**: ❌ Not Created
**Required Features**:
- **API Security Test Results**
  - REST API test results
  - GraphQL API test results
  - Authentication test results
  - Authorization test results
  - Rate limiting test results
  - Vulnerability detection results
  
- **API Security Configuration**
  - API endpoint configuration
  - Security test configuration
  - Test execution

### 17. **Data Pipelines** (`/pipelines` or `/tests/pipelines`)
**Status**: ❌ Not Created
**Required Features**:
- **Pipeline Test Results**
  - ETL pipeline test results
  - Streaming data test results
  - Data transformation test results
  - Pipeline security test results
  
- **Pipeline Configuration**
  - Pipeline definition
  - Test configuration
  - Monitoring setup

### 18. **Distributed Systems** (`/distributed` or `/tests/distributed`)
**Status**: ❌ Not Created
**Required Features**:
- **Distributed System Test Results**
  - Multi-region test results
  - Policy consistency test results
  - Synchronization test results
  - Distributed transaction test results
  
- **Distributed System Configuration**
  - Region configuration
  - Policy consistency rules
  - Test execution

### 19. **Settings** (`/settings`)
**Status**: ❌ Not Created (but referenced in TopNav)
**Required Features**:
- **General Settings**
  - Application settings
  - User preferences
  - Theme settings
  
- **Notification Settings**
  - Email notifications
  - Slack/webhook integrations
  - Notification rules
  
- **Security Settings**
  - Authentication configuration
  - API keys management
  - Access control settings

## Page Priority

### High Priority (Core Functionality)
1. ✅ Dashboard - Partially done, needs trends
2. Tests - Full implementation needed
3. Reports - Full implementation needed
4. Policies - Full implementation needed
5. Violations - Full implementation needed

### Medium Priority (Important Features)
6. History - Full implementation needed
7. Analytics - Full implementation needed
8. Test Suite Builder - New page needed
9. User Simulation - New page needed
10. Resources - New page needed

### Lower Priority (Advanced Features)
11. Contracts - New page needed
12. Datasets - New page needed
13. CI/CD Integration - New page needed
14. Ephemeral Environments - New page needed
15. Integrations - New page needed
16. API Security - New page needed
17. Data Pipelines - New page needed
18. Distributed Systems - New page needed
19. Settings - New page needed

## Navigation Structure

```
Home (/)
├── Dashboard (/dashboard) ✅
├── Tests (/tests)
│   ├── Test Suites List
│   ├── Test Suite Builder (/tests/builder)
│   ├── Test Execution (/tests/run/:id)
│   └── Test Results (/tests/results/:id)
├── Reports (/reports)
│   ├── Reports List
│   ├── Report Viewer (/reports/:id)
│   └── Generate Report (/reports/generate)
├── Policies (/policies)
│   ├── Policy List
│   ├── Policy Editor (/policies/edit/:id)
│   └── Policy Versions (/policies/:id/versions)
├── Analytics (/analytics) ✅
├── Violations (/violations) ✅
├── History (/history) ✅
├── Users (/users) - NEW
├── Resources (/resources) - NEW
├── Contracts (/contracts) - NEW
├── Datasets (/datasets) - NEW
├── Integrations (/integrations) - NEW
│   ├── CI/CD (/integrations/ci-cd)
│   ├── SAST/DAST (/integrations/sast-dast)
│   └── DBT/GE (/integrations/dbt-ge)
├── API Security (/api-security) - NEW
├── Data Pipelines (/pipelines) - NEW
├── Distributed Systems (/distributed) - NEW
└── Settings (/settings) - NEW
```

