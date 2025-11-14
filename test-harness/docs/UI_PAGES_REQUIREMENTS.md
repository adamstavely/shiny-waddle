# TestOrchestrator Front-End UI Pages Requirements

Based on the comprehensive functionality of the TestOrchestrator framework, here are all the UI pages that need to be created:

## Implementation Status Summary

**Total Pages**: 19  
**Fully Implemented**: 14  
**Partially Implemented**: 1 (Dashboard)  
**Not Created**: 4  

### Fully Implemented Pages ✅
1. Tests (`/tests`) - Complete with builder, execution, and results
2. Policies (`/policies`) - Complete with CRUD, versioning, deployment
3. Analytics (`/analytics`) - Complete with trends, charts, and metrics
4. Violations (`/violations`) - Complete with management and tracking
5. History (`/history`) - Complete with execution history, audit logs, and activity feed
6. Test Suite Builder (`/tests/builder`) - Complete wizard implementation
7. Ephemeral Environments (`/environments`) - Complete with management and monitoring
8. Integrations (`/integrations`) - Complete with SAST, DAST, DBT, GE integrations
9. API Security (`/api-security`) - Complete with test results and configuration
10. Data Pipelines (`/pipelines`) - Complete with test results and configuration
11. Settings (`/settings`) - Complete with general, notification, and security settings
12. Reports (`/reports`) - Complete with list, viewer, generation, and scheduling
13. CI/CD Integration (`/ci-cd`) - Complete with GitHub Actions and Jenkins support
14. Distributed Systems (`/distributed-systems`) - Complete with multi-region testing and configuration

### Partially Implemented Pages ⚠️
1. Dashboard (`/dashboard`) - Core features done, missing trends and heatmap

### Not Yet Created Pages ❌
1. User Simulation (`/users`) - Not created
2. Resources (`/resources`) - Not created
3. Contracts (`/contracts`) - Not created
4. Datasets (`/datasets`) - Not created

## Recent Completions

- ✅ **Reports Page** - Fully implemented with report list, viewer with charts, generation modal, download functionality, and API integration
- ✅ **Backend API for Reports** - Complete NestJS module with report generation, download, deletion, and full CRUD operations
- ✅ **CI/CD Integration Page** - Fully implemented with GitHub Actions and Jenkins support, configuration management, run monitoring, and global settings
- ✅ **Backend API for CI/CD** - Complete NestJS module with dual platform support (GitHub Actions and Jenkins), configuration management, and run tracking
- ✅ **Distributed Systems Page** - Fully implemented with multi-region testing, region configuration, policy synchronization, test execution, and detailed result views
- ✅ **Backend API for Distributed Systems** - Complete NestJS module with region management, test execution, and result tracking
- ✅ **Policies Page** - Fully implemented with complete CRUD, versioning, comparison, deployment, rollback, audit logging, and testing interface
- ✅ **Backend API for Policies** - Complete NestJS module with all endpoints for policy management
- ✅ **Settings Page** - Fully implemented with General Settings, Notification Settings, and Security Settings
- ✅ **Tests Page** - Enhanced with comprehensive test suite builder modal, delete functionality, test result detail modal, enhanced execution view with error handling, and export functionality
- ✅ **Data Pipelines Page** - Fully implemented with pipeline test results view, configuration management, and full CRUD operations
- ✅ **Ephemeral Environments Page** - Fully implemented with environment list, management (create/view/cleanup), and monitoring (health, resources, test status)
- ✅ **Analytics Page** - Fully implemented with compliance trends, score analytics, violation patterns, performance metrics, and comprehensive chart visualizations
- ✅ **Backend API for Analytics** - Complete analytics endpoint with time range support, data aggregation from reports, and mock data generation
- ✅ **Test Suite Builder Page** - Fully implemented as standalone wizard page with step-by-step configuration, preview, validation, and save as draft/publish functionality
- ✅ **Chart Components** - Reusable SVG-based chart components (LineChart, MultiLineChart, BarChart, DistributionChart, ComparisonChart, CorrelationChart, ResourceUsageChart)
- ✅ **Integrations Page** - Fully implemented with integration list, configuration modals, connection testing, status monitoring, and results viewing for SAST, DAST, DBT, and Great Expectations
- ✅ **Violations Page** - Fully implemented with violations list, filtering, sorting, violation details modal, comments, remediation tracking, and violation management (assign, resolve, ignore)
- ✅ **Backend API for Violations** - Complete NestJS module with full CRUD, comments, remediation tracking, and timeline management
- ✅ **History Page** - Fully implemented with test execution history, audit logs, activity feed, execution comparison, and comprehensive filtering
- ✅ **Backend API for History** - Complete NestJS module with test executions, audit logs, activities, and comparison functionality
- ✅ **API Security Page** - Fully implemented with API security test results, configuration management, endpoint management, test execution, and detailed result views
- ✅ **Backend API for API Security** - Complete NestJS module with configs, endpoints, test results, and full CRUD operations

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
**Status**: ✅ Created, ✅ Mostly Implemented
**Required Features**:
- **Test Suites List** ✅
  - View all test suites ✅
  - Filter by application, team, status ✅
  - Create new test suite ✅
  - Edit/delete test suites ✅
  - Run test suite ✅
  - Test suite status (passing/failing/pending) ✅
  
- **Test Suite Builder/Editor** ✅
  - Modal-based builder in Tests page ✅
  - Standalone wizard page at `/tests/builder` ✅
  - Configure test types (Access Control, Data Behavior, Contract, Dataset Health) ✅
  - Define user roles and attributes ✅
  - Configure resources and contexts ✅
  - Define test queries ✅
  - Set expected decisions ✅
  - Configure allowed fields, required filters, disallowed joins ✅
  - Contract definitions ✅
  - Dataset configurations ✅
  - Privacy thresholds ✅
  - Statistical fidelity targets ✅
  - Preview and validation ✅
  - Save as draft or publish ✅
  
- **Test Execution** ✅
  - Run test suite interface ✅
  - Real-time test execution progress ✅
  - Test results viewer ✅
  - Pass/fail indicators ✅
  - Error details and stack traces ✅
  - Execution summary with statistics ✅
  - Enhanced error handling and display ✅
  
- **Test Results Detail** ✅
  - Individual test result view ✅
  - Test details breakdown ✅
  - Comparison with previous runs ✅
  - Export test results ✅

### 3. **Reports** (`/reports`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Reports List** ✅
  - View all generated reports ✅
  - Filter by date, application, team, type ✅
  - Report status (generated, pending, failed) ✅
  - Download reports (JSON, HTML, XML) ✅
  
- **Report Viewer** ✅
  - HTML report viewer ✅
  - Report summary with compliance score, test counts ✅
  - Detailed test results ✅
  - Compliance scores breakdown with charts ✅
  - Charts and visualizations (compliance by category) ✅
  - Export options ✅
  
- **Report Generation** ✅
  - Generate new report interface ✅
  - Select test results to include ✅
  - Choose report format (HTML, JSON, XML) ✅
  - Schedule automated reports (basic structure) ✅
  - Date range filters ✅
  - Application/team/validator filters ✅
  - Include charts and details options ✅

**Backend API**: ✅ Complete (reports module with generation, download, deletion, and full CRUD operations)

**Implementation Details**:
- Report generation modal with comprehensive options ✅
- Real-time API integration for loading and generating reports ✅
- Enhanced report viewer with summary cards, charts, and detailed content ✅
- Progress bars for compliance by category visualization ✅
- Download functionality for all report formats ✅
- Report deletion with confirmation ✅

### 4. **Policies** (`/policies`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Policy List** ✅
  - View all policies (RBAC and ABAC) ✅
  - Filter by type, status, application ✅
  - Policy status (active, draft, deprecated) ✅
  - Create new policy ✅
  - Edit/delete policies ✅
  
- **Policy Editor** ✅
  - RBAC policy editor ✅
  - ABAC policy editor ✅
  - Policy rule builder (visual/form-based) ✅
  - Condition editor with operators ✅
  - Policy validation ✅
  - Policy testing interface ✅
  - Policy preview ✅
  
- **Policy Management** ✅
  - Policy versioning ✅
  - Policy comparison (diff view) ✅
  - Policy deployment ✅
  - Policy rollback ✅
  - Policy audit log ✅
  
**Backend API**: ✅ Complete (policies module with full CRUD, versioning, deployment, rollback, audit logging)

### 5. **Analytics** (`/analytics`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Compliance Trends** ✅
  - Compliance score over time (line charts) ✅
  - Trends by application ✅
  - Trends by team ✅
  - Trends by category ✅
  
- **Score Analytics** ✅
  - Score distribution charts ✅
  - Score breakdown by test type ✅
  - Score comparison across applications/teams ✅
  
- **Violation Patterns** ✅
  - Most common violations ✅
  - Violation frequency charts ✅
  - Violation trends ✅
  - Violation correlation analysis ✅
  
- **Performance Metrics** ✅
  - Test execution time trends ✅
  - Test suite performance ✅
  - Resource usage metrics ✅

**Backend API**: ✅ Complete (analytics endpoint with time range support, mock data generation, and real data from reports)

**Implementation Details**:
- Time range selector (7, 30, 90, 365 days) ✅
- Reusable chart components (LineChart, MultiLineChart, BarChart, DistributionChart, ComparisonChart, CorrelationChart, ResourceUsageChart) ✅
- Compliance trends with current score and change indicators ✅
- Score analytics with distribution histograms and comparisons ✅
- Violation patterns with correlation matrix visualization ✅
- Performance metrics with CPU, memory, and network usage tracking ✅
- Responsive grid layout with interactive SVG-based charts ✅
- Real-time data loading from API with fallback to mock data ✅

### 6. **Violations** (`/violations`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Violations List** ✅
  - View all violations ✅
  - Filter by severity, type, application, team, status ✅
  - Sort by date, severity, application ✅
  - Violation status (open, in-progress, resolved, ignored) ✅
  
- **Violation Details** ✅
  - Violation description ✅
  - Affected resources ✅
  - Test results that triggered violation ✅
  - Policy that was violated ✅
  - Remediation suggestions ✅
  
- **Violation Management** ✅
  - Assign violations ✅
  - Add comments/notes ✅
  - Mark as resolved ✅
  - Ignore violations ✅
  - Link to related violations ✅
  
- **Remediation Tracking** ✅
  - Remediation status ✅
  - Remediation timeline ✅
  - Verification tests ✅

**Backend API**: ✅ Complete (violations module with full CRUD, comments, remediation tracking)

### 7. **History** (`/history`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Test Execution History** ✅
  - Timeline view of all test executions ✅
  - Filter by date range, application, team, status ✅
  - Test execution details ✅
  - Compare executions ✅
  
- **Audit Logs** ✅
  - User actions log ✅
  - Policy changes log ✅
  - Test suite changes log ✅
  - System events log ✅
  - Filter and search capabilities ✅
  
- **Activity Feed** ✅
  - Recent activities ✅
  - Test runs ✅
  - Policy updates ✅
  - Report generations ✅
  - Violation resolutions ✅

**Backend API**: ✅ Complete (history module with test executions, audit logs, activities, and comparison functionality)

## Additional Pages Needed

### 8. **Test Suite Builder** (`/tests/builder` or `/tests/new`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- Step-by-step test suite creation wizard ✅
- Test type selection ✅
- Configuration forms for each test type ✅
- Preview and validation ✅
- Save as draft or publish ✅

**Implementation Details**:
- 6-step wizard with progress indicator and step navigation ✅
- Step 1: Basic Information (name, application, team, test types with descriptions) ✅
- Step 2: User Roles & Attributes (tag-based input with add/remove) ✅
- Step 3: Resources (with AddResourceModal for add/edit/remove) ✅
- Step 4: Contexts (with AddContextModal for IP, location, time, device) ✅
- Step 5: Test Type Configurations:
  - Access Control: Expected decisions configuration ✅
  - Data Behavior: Test queries, allowed fields, required filters ✅
  - Contract: Contract definitions ✅
  - Dataset Health: Dataset configurations ✅
- Step 6: Preview & Validation with comprehensive error checking ✅
- Form validation at each step with canProceed checks ✅
- Save as draft and publish functionality with API integration ✅
- Route support for both create (`/tests/builder`) and edit (`/tests/builder/:id`) ✅

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
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **CI/CD Configuration** ✅
  - GitHub Actions workflow configuration ✅
  - Jenkins configuration ✅
  - Compliance threshold settings ✅
  - Merge blocking rules ✅
  - Notification settings ✅
  
- **CI/CD Status** ✅
  - Recent CI/CD runs (GitHub Actions) ✅
  - Recent builds (Jenkins) ✅
  - PR compliance status ✅
  - Blocked merges/builds ✅
  - CI/CD logs ✅
  - Run/build details modal ✅

**Backend API**: ✅ Complete (cicd module with GitHub Actions and Jenkins support, configuration management, run tracking)

**Implementation Details**:
- Dual platform support (GitHub Actions and Jenkins) ✅
- Separate configuration tabs for each platform ✅
- GitHub Actions: repository, workflow file, compliance threshold, merge blocking, PR comments, token configuration ✅
- Jenkins: URL, job name, compliance threshold, build blocking, credentials, pipeline script editor ✅
- Recent runs/builds monitoring with status indicators ✅
- Run details modal with test results, logs, and metadata ✅
- Global settings tab with compliance thresholds, merge blocking rules, and notification settings ✅
- Support for email, Slack, and webhook notifications ✅
- Real-time status tracking with refresh functionality ✅

### 14. **Ephemeral Environments** (`/environments` or `/ephemeral`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Environment List** ✅
  - View all ephemeral environments ✅
  - Filter by PR, branch, status ✅
  - Environment status (active, completed, failed) ✅
  
- **Environment Management** ✅
  - Create environment for PR ✅
  - Environment details ✅
  - Test results from environment ✅
  - Environment cleanup ✅
  
- **Environment Monitoring** ✅
  - Environment health ✅
  - Resource usage ✅
  - Test execution status ✅

### 15. **Integrations** (`/integrations`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Integration List** ✅
  - SAST integration ✅
  - DAST integration ✅
  - DBT integration ✅
  - Great Expectations integration ✅
  - Other integrations ✅
  
- **Integration Configuration** ✅
  - Configure each integration ✅
  - Test integration connection ✅
  - Integration status monitoring ✅
  
- **Integration Results** ✅
  - View results from each integration ✅
  - Integration-specific dashboards ✅

**Implementation Details**:
- Integration cards with status indicators (Connected, Disconnected, Error, Pending) ✅
- Configuration modals for each integration type:
  - SAST: Tool selection (SonarQube, Checkmarx, Veracode, Snyk), API endpoint, token, project key, source path ✅
  - DAST: Tool selection (OWASP ZAP, Burp Suite, Nikto, Nmap), API URL, tool endpoint, API key, scan profile ✅
  - DBT: Project path, profiles path, profile name, target ✅
  - Great Expectations: Data context root directory, suite name, expectation suite name ✅
- Connection testing functionality with loading states ✅
- Enable/disable toggle for each integration ✅
- Results modal with summary statistics (total, passed, failed, last run) ✅
- Detailed test results display with pass/fail indicators, timestamps, details, and error messages ✅
- Run integration functionality to execute tests ✅
- Last run tracking and results count display ✅
- Responsive grid layout with integration-specific icons ✅

### 16. **API Security** (`/api-security` or `/tests/api-security`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **API Security Test Results** ✅
  - REST API test results ✅
  - GraphQL API test results ✅
  - Authentication test results ✅
  - Authorization test results ✅
  - Rate limiting test results ✅
  - Vulnerability detection results ✅
  
- **API Security Configuration** ✅
  - API endpoint configuration ✅
  - Security test configuration ✅
  - Test execution ✅

**Backend API**: ✅ Complete (api-security module with configs, endpoints, test results, and full CRUD operations)

**Implementation Details**:
- Configuration management with authentication and rate limiting settings ✅
- Endpoint management with REST/GraphQL support ✅
- Test execution with detailed results ✅
- Test results display with status indicators, security issues, and vulnerability details ✅
- Filtering by type, status, and search ✅
- Detailed result modal with authentication, authorization, rate limiting, and vulnerability information ✅

### 17. **Data Pipelines** (`/pipelines` or `/tests/pipelines`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Pipeline Test Results** ✅
  - ETL pipeline test results ✅
  - Streaming data test results ✅
  - Data transformation test results ✅
  - Pipeline security test results ✅
  
- **Pipeline Configuration** ✅
  - Pipeline definition ✅
  - Test configuration ✅
  - Monitoring setup ✅

### 18. **Distributed Systems** (`/distributed` or `/tests/distributed`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **Distributed System Test Results** ✅
  - Multi-region test results ✅
  - Policy consistency test results ✅
  - Synchronization test results ✅
  - Distributed transaction test results ✅
  - Eventual consistency test results ✅
  
- **Distributed System Configuration** ✅
  - Region configuration (add/edit/delete) ✅
  - Policy consistency rules ✅
  - Policy synchronization settings ✅
  - Test execution interface ✅

**Backend API**: ✅ Complete (distributed-systems module with region management, test execution, and result tracking)

**Implementation Details**:
- Test results tab with filtering by test type, region, and status ✅
- Region configuration tab with region management (ID, name, endpoint, PDP endpoint, timezone, latency) ✅
- Policy synchronization configuration (enable/disable, sync interval, consistency level) ✅
- Test execution modal with test type selection, region selection, user/resource/action configuration ✅
- Test result cards with region preview, consistency status, performance metrics ✅
- Detailed test result modal with:
  - Test summary (status, type, latency, regions tested) ✅
  - Consistency check results with inconsistency details ✅
  - Synchronization check results ✅
  - Performance metrics (total time, average latency, fastest/slowest regions) ✅
  - Region-by-region results with decisions and errors ✅
- Support for policy-consistency, multi-region, synchronization, transaction, and eventual-consistency test types ✅

### 19. **Settings** (`/settings`)
**Status**: ✅ Created, ✅ Fully Implemented
**Required Features**:
- **General Settings** ✅
  - Application settings ✅
  - User preferences ✅
  - Theme settings ✅
  
- **Notification Settings** ✅
  - Email notifications ✅
  - Slack/webhook integrations ✅
  - Notification rules ✅
  
- **Security Settings** ✅
  - Authentication configuration ✅
  - API keys management ✅
  - Access control settings ✅

## Page Priority

### High Priority (Core Functionality)
1. ✅ Dashboard - Partially done, needs trends
2. ✅ Tests - Fully implemented (enhanced builder, execution, results)
3. ✅ Reports - Fully implemented
4. ✅ Policies - Fully implemented
5. ✅ Violations - Fully implemented

### Medium Priority (Important Features)
6. ✅ History - Fully implemented
7. ✅ Analytics - Fully implemented
8. ✅ Test Suite Builder - Fully implemented
9. User Simulation - New page needed
10. Resources - New page needed

### Lower Priority (Advanced Features)
11. Contracts - New page needed
12. Datasets - New page needed
13. ✅ CI/CD Integration - Fully implemented (GitHub Actions & Jenkins)
14. ✅ Ephemeral Environments - Fully implemented
15. ✅ Integrations - Fully implemented
16. ✅ API Security - Fully implemented
17. ✅ Data Pipelines - Fully implemented
18. ✅ Distributed Systems - Fully implemented
19. ✅ Settings - Fully implemented

## Navigation Structure

```
Home (/)
├── Dashboard (/dashboard) ✅
├── Tests (/tests) ✅
│   ├── Test Suites List ✅
│   ├── Test Suite Builder (/tests/builder) ✅
│   ├── Test Execution ✅
│   └── Test Results ✅
├── Reports (/reports) ✅
│   ├── Reports List ✅
│   ├── Report Viewer ✅
│   └── Generate Report ✅
├── Policies (/policies) ✅
│   ├── Policy List ✅
│   ├── Policy Editor (/policies/edit/:id) ✅
│   └── Policy Versions (/policies/:id/versions) ✅
├── Analytics (/analytics) ✅
├── Violations (/violations) ✅
├── History (/history) ✅
├── Users (/users) - NEW
├── Resources (/resources) - NEW
├── Contracts (/contracts) - NEW
├── Datasets (/datasets) - NEW
├── Integrations (/integrations) ✅
│   ├── CI/CD (/ci-cd) ✅
│   ├── SAST/DAST ✅
│   └── DBT/GE ✅
├── API Security (/api-security) ✅
├── Data Pipelines (/pipelines) ✅
├── Ephemeral Environments (/environments) ✅
├── Distributed Systems (/distributed-systems) ✅
└── Settings (/settings) ✅
```

