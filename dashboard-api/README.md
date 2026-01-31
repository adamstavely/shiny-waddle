# Heimdall Dashboard API

NestJS backend API for the Heimdall compliance dashboard.

## Setup

```bash
npm install
```

## Development

```bash
npm run start:dev
```

The API will run on http://localhost:3001

## Production

```bash
npm run build
npm run start:prod
```

## API Endpoints

### Dashboard
- `GET /api/dashboard-data` - Get dashboard data
- `GET /api/reports` - Get compliance reports

### Policy Builder (Phase 4 Complete ✅)

#### Policy Management
- `GET /api/policies` - List all policies
- `POST /api/policies` - Create policy
- `GET /api/policies/:id` - Get policy details
- `PATCH /api/policies/:id` - Update policy
- `DELETE /api/policies/:id` - Delete policy

#### Policy Versioning & Comparison
- `GET /api/policies/:id/versions` - Get policy versions
- `GET /api/policies/:id/diff` - Compare policy versions
- `GET /api/policies/:id/system-state-comparison` - Compare expected vs actual

#### Gap Analysis
- `GET /api/policies/enforcement-gaps` - Get enforcement gaps
- `GET /api/policies/:id/gap-analysis` - Analyze gaps for policy

#### AI Summaries & Recommendations
- `GET /api/policies/summaries/executive` - Generate executive summary
- `GET /api/policies/summaries/detailed` - Generate detailed summary
- `GET /api/policies/summaries/compliance` - Generate compliance summary
- `GET /api/policies/:id/recommendations` - Get AI recommendations
- `POST /api/policies/query` - Natural language query

#### Compliance & Trends
- `GET /api/policies/compliance/trends` - Get compliance trends
- `GET /api/policies/compliance-analysis` - Get compliance analysis

#### Scheduled Reports
- `GET /api/policies/reports/scheduled` - List scheduled reports
- `POST /api/policies/reports/scheduled` - Create scheduled report
- `PATCH /api/policies/reports/scheduled/:id` - Update report
- `DELETE /api/policies/reports/scheduled/:id` - Delete report
- `POST /api/policies/reports/scheduled/:id/run` - Run report manually

#### Automation
- `GET /api/policies/automation/rules` - List automation rules
- `POST /api/policies/automation/rules` - Create automation rule
- `PATCH /api/policies/automation/rules/:id` - Update rule
- `DELETE /api/policies/automation/rules/:id` - Delete rule
- `POST /api/policies/automation/gap-analysis/run` - Run scheduled gap analysis

#### Notifications
- `GET /api/policies/notifications/history` - Get notification history
- `GET /api/policies/notifications/preferences` - Get preferences
- `PATCH /api/policies/notifications/preferences` - Update preferences

#### Collaboration
- `GET /api/policies/:id/comments` - Get policy comments
- `POST /api/policies/:id/comments` - Add comment
- `PATCH /api/policies/comments/:commentId` - Update comment
- `DELETE /api/policies/comments/:commentId` - Delete comment
- `GET /api/policies/:id/approvals` - Get approval requests
- `POST /api/policies/:id/approvals` - Create approval request
- `POST /api/policies/approvals/:approvalId/approve` - Approve policy
- `POST /api/policies/approvals/:approvalId/reject` - Reject policy

#### Templates
- `GET /api/policies/templates` - List policy templates
- `POST /api/policies/templates` - Create template
- `GET /api/policies/templates/:id` - Get template
- `PATCH /api/policies/templates/:id` - Update template
- `DELETE /api/policies/templates/:id` - Delete template

## Environment Variables

See main [README.md](../README.md) for full configuration options.

### Policy Builder Specific
```bash
# LLM Integration (optional)
LLM_PROVIDER=openai|anthropic|azure|disabled
LLM_API_KEY=your_api_key
LLM_MODEL=gpt-4-turbo-preview
LLM_TEMPERATURE=0.7
LLM_MAX_TOKENS=2000

# Caching
CACHE_TTL=3600  # Cache TTL in seconds
```

## Services

### Policy Services
- **PoliciesService** - Core policy CRUD operations
- **PolicyVersioningService** - Policy version management
- **PolicyDiffService** - Policy comparison and diff
- **GapAnalysisService** - Compliance gap analysis
- **SystemStateComparisonService** - Expected vs actual comparison
- **DataTagComparisonService** - Tag comparison
- **AISummaryService** - AI-powered summary generation
- **LLMIntegrationService** - LLM provider integration
- **CacheService** - Performance caching
- **ReportSchedulerService** - Scheduled report generation
- **AutomationService** - Automation rules and remediation
- **PolicyNotificationsService** - Policy change notifications
- **CollaborationService** - Comments and approvals

For detailed API documentation, see [API Documentation](../docs/api/API.md).

