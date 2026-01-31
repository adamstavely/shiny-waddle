# Heimdall Dashboard Frontend

Vue.js frontend for the Heimdall compliance dashboard.

## Setup

```bash
npm install
```

## Development

```bash
npm run dev
```

The frontend will run on http://localhost:5173

## Build

```bash
npm run build
```

## Preview Production Build

```bash
npm run preview
```

## Policy Builder Components (Phase 4 Complete ✅)

### Core Components
- **PolicyVisualBuilder.vue** - Visual drag-and-drop policy builder
- **PolicyRuleBuilder.vue** - Rule and condition builder
- **PolicyJSONEditor.vue** - Monaco-based JSON editor
- **PolicyVisualization.vue** - Interactive policy visualization

### Comparison & Analysis Components
- **PolicyDiffViewer.vue** - Policy version comparison viewer
- **GapAnalysisView.vue** - Compliance gap analysis
- **SystemStateDiffPanel.vue** - Expected vs actual comparison
- **TagComparisonPanel.vue** - Data tag comparison

### AI & Reporting Components
- **AISummaryView.vue** - AI-powered policy summaries with PDF/HTML export
- **PolicyRecommendations.vue** - AI-generated policy recommendations
- **NaturalLanguageQuery.vue** - Natural language query interface
- **ComplianceTrendsChart.vue** - Interactive compliance trends chart
- **ScheduledReports.vue** - Scheduled report management

### Collaboration Components
- **PolicyComments.vue** - Policy comments with @mentions
- **PolicyApprovals.vue** - Multi-stage approval workflows

### Views
- **AccessControlPolicies.vue** - Main policy management view
- **ComplianceDashboard.vue** - Compliance dashboard with trends
- **PolicySummaries.vue** - Standalone summaries page

## Dependencies

### Policy Builder Specific
- **vue-draggable-next** - Drag-and-drop functionality
- **monaco-editor** - JSON code editor
- **chart.js** / **vue-chartjs** - Chart visualizations
- **jspdf** / **html2canvas** - PDF export
- **lucide-vue-next** - Icons

## Routes

- `/policies/access-control` - Policy management
- `/policies/compliance` - Compliance dashboard
- `/policies/summaries` - AI summaries

For detailed component documentation, see [Policy Builder Phase 4 Plan](../docs/development/POLICY_BUILDER_PHASE4_IMPLEMENTATION_PLAN.md).

