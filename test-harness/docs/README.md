# TestOrchestrator Documentation

Welcome to the TestOrchestrator documentation. This directory contains comprehensive guides for using the framework.

## Documentation Structure

The documentation is organized into the following categories:

- **[Guides](./guides/)** - User guides and how-to documentation
- **[API Documentation](./api/)** - Technical API and service documentation
- **[Product Documentation](./product/)** - Product requirements, roadmaps, and planning
- **[UI Documentation](./ui/)** - UI requirements, design, and accessibility

## Documentation Index

### Getting Started

- **[Policy Creation Guide](./guides/POLICY_CREATION_GUIDE.md)**: Learn how to create RBAC and ABAC policies
  - RBAC policy structure and syntax
  - ABAC policy structure and syntax
  - Condition operators and logical operators
  - Best practices and examples
  - Troubleshooting tips

- **[Test Creation Guide](./guides/TEST_CREATION_GUIDE.md)**: Learn how to create test suites
  - Test suite structure
  - Access control tests
  - Contract tests
  - Dataset health tests
  - Best practices and examples

- **[Quick Reference](./guides/QUICK_REFERENCE.md)**: Quick reference for common tasks
  - Policy templates
  - Test suite templates
  - Common patterns
  - Troubleshooting checklist

- **[User Guide](./guides/USER_GUIDE.md)**: Comprehensive user guide for the platform
  - Getting started
  - Core concepts
  - Common workflows
  - Best practices

## Quick Links

### Guides

- [Policy Creation Guide](./guides/POLICY_CREATION_GUIDE.md)
- [Test Creation Guide](./guides/TEST_CREATION_GUIDE.md)
- [Validator Creation Guide](./guides/VALIDATOR_CREATION_GUIDE.md)
- [Extensibility Guide](./guides/EXTENSIBILITY_GUIDE.md)
- [User Guide](./guides/USER_GUIDE.md)
- [Quick Reference](./guides/QUICK_REFERENCE.md)

### API & Technical Documentation

- [API Documentation](./api/API.md) - Complete API reference
- [Services Documentation](./api/SERVICES.md) - Service implementation guide
- [Testing Guide](./api/TESTING.md) - Testing documentation
- [Test Hierarchy and Relationships](./api/TEST_HIERARCHY_AND_RELATIONSHIPS.md) - Test structure reference

### Product Documentation

- [PRD](./product/PRD.md) - Product Requirements Document
- [PRD Gap Analysis](./product/PRD_GAP_ANALYSIS.md) - Gap analysis between PRD and implementation
- [Feature Roadmap](./product/FEATURE_ROADMAP.md) - Recommended enhancements and future features
- [ASPM Enhancement Roadmap](./product/ASPM_ENHANCEMENT_ROADMAP.md) - ASPM platform roadmap
- [Executive Overview](./product/HEIMDALL_EXECUTIVE_OVERVIEW.md) - Executive presentation/overview
- [Aura Inspector Integration Plan](./product/AURA_INSPECTOR_INTEGRATION_PLAN.md) - Integration plan

### UI Documentation

- [UI Requirements](./ui/UI_REQUIREMENTS.md) - UI requirements documentation
- [UI Pages Requirements](./ui/UI_PAGES_REQUIREMENTS.md) - UI pages requirements
- [Test Management UI Redesign](./ui/TEST_MANAGEMENT_UI_REDESIGN.md) - UI redesign plan
- [Accessibility Checklist](./ui/ACCESSIBILITY_CHECKLIST.md) - Accessibility compliance checklist
- [WCAG Compliance](./ui/WCAG_COMPLIANCE.md) - WCAG compliance documentation

## Dashboard Setup

The Heimdall dashboard has been rewritten with:
- **Backend**: NestJS (Node.js framework)
- **Frontend**: Vue.js 3 with Composition API

### Quick Start

#### 1. Install Dependencies

From the `test-harness` directory:

```bash
npm run dashboard:install
```

Or manually:

```bash
cd dashboard-api && npm install
cd ../dashboard-frontend && npm install
```

#### 2. Start the Backend (NestJS API)

In one terminal:

```bash
npm run dashboard:api
```

Or manually:

```bash
cd dashboard-api
npm run start:dev
```

The API will run on **http://localhost:3001**

#### 3. Start the Frontend (Vue.js)

In another terminal:

```bash
npm run dashboard:frontend
```

Or manually:

```bash
cd dashboard-frontend
npm run dev
```

The frontend will run on **http://localhost:5173**

### Architecture

#### Backend Structure (`dashboard-api/`)

```
dashboard-api/
├── src/
│   ├── main.ts                 # NestJS bootstrap
│   ├── app.module.ts           # Root module
│   └── dashboard/
│       ├── dashboard.module.ts # Dashboard module
│       ├── dashboard.controller.ts # API endpoints
│       └── dashboard.service.ts    # Business logic
├── package.json
└── tsconfig.json
```

**API Endpoints:**
- `GET /api/dashboard-data` - Returns dashboard data (compliance scores, test results)
- `GET /api/reports` - Returns compliance reports

#### Frontend Structure (`dashboard-frontend/`)

```
dashboard-frontend/
├── src/
│   ├── main.ts                 # Vue app entry point
│   ├── App.vue                 # Root component
│   ├── style.css               # Global styles
│   └── components/
│       ├── Header.vue          # Dashboard header
│       ├── OverallScore.vue   # Overall compliance score display
│       ├── ScoreCard.vue      # Score cards (by app/team)
│       ├── CategoryScores.vue # Category breakdown with progress bars
│       └── TestResultsTable.vue # Recent test results table
├── index.html
├── vite.config.ts             # Vite configuration
└── package.json
```

### Features

- **Real-time Dashboard**: Auto-refreshes every 30 seconds
- **Responsive Design**: Works on desktop and mobile
- **Component-based**: Modular Vue components
- **Type-safe**: Full TypeScript support
- **Modern Stack**: Vue 3 Composition API + Vite

### Development

#### Backend Development

```bash
cd dashboard-api
npm run start:dev  # Watch mode with hot reload
```

#### Frontend Development

```bash
cd dashboard-frontend
npm run dev  # Vite dev server with HMR
```

### Production Build

#### Backend

```bash
cd dashboard-api
npm run build
npm run start:prod
```

#### Frontend

```bash
cd dashboard-frontend
npm run build
# Output in dist/ directory
```

### Troubleshooting

#### Port Already in Use

If port 3001 (API) or 5173 (Frontend) is already in use:

- **API**: Set `PORT` environment variable: `PORT=3002 npm run start:dev`
- **Frontend**: Update `vite.config.ts` port setting

#### CORS Issues

The API is configured to allow requests from `http://localhost:5173`. If you change the frontend port, update the CORS configuration in `dashboard-api/src/main.ts`.

#### No Dashboard Data

If you see sample data, run compliance tests first:

```bash
npm run test:compliance
```

This generates `dashboard-data.json` in the `reports/` directory.

## Common Tasks

### Creating Your First Policy

1. Read the [Policy Creation Guide](./guides/POLICY_CREATION_GUIDE.md)
2. Choose RBAC or ABAC based on your needs
3. Create a policy file in `policies/` directory
4. Load and test your policy

### Creating Your First Test Suite

1. Read the [Test Creation Guide](./guides/TEST_CREATION_GUIDE.md)
2. Create a test suite file in `tests/suites/`
3. Define resources, users, and test queries
4. Run the test suite

### Creating a Validator

1. Read the [Validator Creation Guide](./guides/VALIDATOR_CREATION_GUIDE.md)
2. Review the [Extensibility Guide](./guides/EXTENSIBILITY_GUIDE.md)
3. Implement your validator following the patterns

### Troubleshooting

Both guides include troubleshooting sections:
- [Policy Troubleshooting](./guides/POLICY_CREATION_GUIDE.md#troubleshooting)
- [Test Troubleshooting](./guides/TEST_CREATION_GUIDE.md#troubleshooting)

## Examples

See the [examples](../examples/) directory for complete working examples:
- `basic-usage.ts`: Basic TestOrchestrator usage
- `abac-usage.ts`: ABAC policy usage

## Additional Resources

- [Main README](../README.md): Framework overview and features
- [Policy Examples](../policies/): Reference policy implementations
- [Test Examples](../tests/): Reference test suite implementations
