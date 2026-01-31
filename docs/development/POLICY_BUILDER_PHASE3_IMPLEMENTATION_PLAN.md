# Policy Builder Phase 3 Implementation Plan

**Date:** January 31, 2026  
**Status:** 📋 Planning  
**Priority:** High  
**Dependencies:** Phase 1 Complete ✅, Phase 2 Mostly Complete ✅

---

## Executive Summary

Phase 3 focuses on **completing Phase 2 integration**, implementing **AI-Powered Summaries**, and enhancing the overall user experience with improved workflows. This phase builds upon the solid foundation established in Phases 1 and 2, making all comparison and analysis features easily accessible and adding intelligent summarization capabilities.

---

## Phase 3 Goals

1. **Complete Phase 2 Integration** - Integrate all Phase 2 components (Gap Analysis, System State Comparison, Tag Comparison) into accessible UI workflows
2. **AI-Powered Summary Generation** - Generate executive and detailed summaries of policy changes and compliance status
3. **Enhanced User Experience** - Improve navigation, workflows, and accessibility of all policy management features
4. **Workflow Improvements** - Streamline common tasks like policy comparison, gap remediation, and compliance tracking

---

## Current State Analysis

### Phase 1 Implementation ✅

**Frontend:**
- `PolicyVisualBuilder.vue` - Visual drag-and-drop policy builder ✅
- `PolicyRuleBuilder.vue` - Rule/condition builder component ✅
- `PolicyJSONEditor.vue` - Monaco-based JSON editor ✅
- `AccessControlPolicies.vue` - Main policy management view ✅

**Backend:**
- Policy CRUD operations ✅
- Policy versioning ✅
- Template management ✅

### Phase 2 Implementation Status

**Backend Services (Complete):**
- ✅ `PolicyDiffService` - Version comparison with structure diff
- ✅ `SystemStateComparisonService` - Expected vs actual comparison
- ✅ `DataTagComparisonService` - Tag comparison and guidance
- ✅ `GapAnalysisService` - Comprehensive gap analysis

**Frontend Components (Created but Not Fully Integrated):**
- ✅ `PolicyDiffViewer.vue` - Integrated into AccessControlPolicies ✅
- ✅ `GapAnalysisView.vue` - **Exists but NOT integrated**
- ✅ `SystemStateDiffPanel.vue` - **Exists but NOT integrated**
- ✅ `TagComparisonPanel.vue` - **Exists but NOT integrated**
- ✅ `RemediationGuide.vue` - **Exists but NOT integrated**

**API Endpoints (Complete):**
- ✅ Version comparison endpoints
- ✅ System state comparison endpoints
- ✅ Tag comparison endpoints
- ✅ Gap analysis endpoints

**Integration Gaps:**
- ❌ Gap Analysis View not accessible from policy management
- ❌ System State Comparison not accessible from policy detail view
- ❌ Tag Comparison not accessible from policy detail view
- ❌ No dedicated compliance dashboard
- ❌ No AI summary generation

---

## Architecture Overview

### Component Integration Structure

```
AccessControlPolicies.vue (Main View)
├── Policy Cards (with actions)
│   ├── Compare Versions ✅ (opens PolicyDiffViewer)
│   ├── View Gap Analysis ❌ (NEW - opens GapAnalysisView)
│   ├── Compare System State ❌ (NEW - opens SystemStateDiffPanel)
│   └── View Compliance ❌ (NEW - opens compliance dashboard)
│
├── Policy Detail Modal (Enhanced)
│   ├── Basic Info Tab ✅
│   ├── Rules/Conditions Tab ✅
│   ├── Visual Builder Tab ✅
│   ├── Preview Tab ✅
│   ├── Versions Tab ❌ (NEW)
│   ├── Comparison Tab ❌ (NEW - SystemStateDiffPanel)
│   ├── Gap Analysis Tab ❌ (NEW - GapAnalysisView)
│   └── Tags Tab ❌ (NEW - TagComparisonPanel)
│
└── Compliance Dashboard (NEW)
    ├── Overview Cards
    ├── Gap Analysis View
    ├── Compliance Trends
    └── Remediation Tracking
```

### Backend Services (New)

```
Backend Services:
├── AISummaryService (NEW)
│   ├── generateExecutiveSummary() - High-level summary
│   ├── generateDetailedSummary() - Technical breakdown
│   ├── generateComplianceSummary() - Compliance status summary
│   └── generateChangeSummary() - Policy change summary
└── ComplianceDashboardService (NEW)
    ├── getComplianceOverview() - Overall compliance metrics
    ├── getComplianceTrends() - Historical trends
    └── getRemediationProgress() - Progress tracking
```

---

## Implementation Phases

### Phase 3.1: Complete Phase 2 Integration (Week 1-2)

**Goal:** Make all Phase 2 components easily accessible from the policy management interface

#### 3.1.1: Enhance Policy Detail Modal

**File:** `dashboard-frontend/src/views/policies/AccessControlPolicies.vue`

**Changes:**
1. Add new tabs to policy detail modal:
   - **Versions Tab** - Show version history with comparison actions
   - **Comparison Tab** - System state comparison (SystemStateDiffPanel)
   - **Gap Analysis Tab** - Gap analysis view (GapAnalysisView)
   - **Tags Tab** - Tag comparison (TagComparisonPanel)

2. Add action buttons to policy cards:
   - "View Gaps" - Opens gap analysis for the policy
   - "Compare State" - Opens system state comparison
   - "View Tags" - Opens tag comparison (if applicable)

**Implementation:**

```vue
<!-- Add to policy detail modal tabs -->
<div class="modal-tabs">
  <button @click="detailTab = 'basic'" :class="{ active: detailTab === 'basic' }">
    Basic Info
  </button>
  <button @click="detailTab = 'rules'" :class="{ active: detailTab === 'rules' }">
    Rules/Conditions
  </button>
  <button @click="detailTab = 'visual'" :class="{ active: detailTab === 'visual' }">
    Visual Builder
  </button>
  <button @click="detailTab = 'preview'" :class="{ active: detailTab === 'preview' }">
    Preview
  </button>
  <button @click="detailTab = 'versions'" :class="{ active: detailTab === 'versions' }">
    Versions
  </button>
  <button @click="detailTab = 'comparison'" :class="{ active: detailTab === 'comparison' }">
    System State
  </button>
  <button @click="detailTab = 'gaps'" :class="{ active: detailTab === 'gaps' }">
    Gap Analysis
  </button>
  <button @click="detailTab = 'tags'" :class="{ active: detailTab === 'tags' }">
    Tags
  </button>
</div>

<!-- Add tab content -->
<div v-if="detailTab === 'comparison'" class="tab-content">
  <SystemStateDiffPanel :policy-id="editingPolicy" />
</div>

<div v-if="detailTab === 'gaps'" class="tab-content">
  <GapAnalysisView :policy-id="editingPolicy" />
</div>

<div v-if="detailTab === 'tags'" class="tab-content">
  <TagComparisonPanel 
    v-if="selectedResourceId"
    :resource-id="selectedResourceId"
    :policy-id="editingPolicy"
  />
  <div v-else class="empty-state">
    <p>Select a resource to compare tags</p>
  </div>
</div>
```

**Acceptance Criteria:**
- ✅ All Phase 2 components accessible from policy detail modal
- ✅ Navigation between tabs is smooth
- ✅ Components load correctly with policy context
- ✅ Error handling for missing data

#### 3.1.2: Create Compliance Dashboard View

**File:** `dashboard-frontend/src/views/policies/ComplianceDashboard.vue` (NEW)

**Features:**
- Overview cards showing:
  - Total policies
  - Compliance score
  - Total gaps
  - Critical gaps count
- Gap analysis view (reuse GapAnalysisView)
- Compliance trends chart
- Remediation progress tracking
- Quick actions (analyze all, export report)

**Implementation:**

```vue
<template>
  <div class="compliance-dashboard">
    <Breadcrumb :items="breadcrumbItems" />
    <div class="page-header">
      <h1>Compliance Dashboard</h1>
      <div class="header-actions">
        <button @click="refreshAll" class="btn-secondary">Refresh</button>
        <button @click="exportReport" class="btn-primary">Export Report</button>
      </div>
    </div>

    <!-- Overview Cards -->
    <div class="overview-cards">
      <OverviewCard
        title="Total Policies"
        :value="overview.totalPolicies"
        icon="Shield"
      />
      <OverviewCard
        title="Compliance Score"
        :value="`${overview.complianceScore}%`"
        :status="getComplianceStatus(overview.complianceScore)"
        icon="Gauge"
      />
      <OverviewCard
        title="Total Gaps"
        :value="overview.totalGaps"
        :status="overview.totalGaps > 0 ? 'warning' : 'success'"
        icon="AlertCircle"
      />
      <OverviewCard
        title="Critical Gaps"
        :value="overview.criticalGaps"
        :status="overview.criticalGaps > 0 ? 'error' : 'success'"
        icon="AlertTriangle"
      />
    </div>

    <!-- Gap Analysis -->
    <GapAnalysisView />

    <!-- Compliance Trends -->
    <ComplianceTrendsChart :data="trendsData" />
  </div>
</template>
```

**Acceptance Criteria:**
- ✅ Dashboard displays accurate compliance metrics
- ✅ Gap analysis is accessible
- ✅ Trends chart displays historical data
- ✅ Export functionality works

#### 3.1.3: Add Navigation Links

**Files:**
- `dashboard-frontend/src/components/Navigation.vue` or router configuration
- `dashboard-frontend/src/router/index.ts`

**Changes:**
1. Add route for Compliance Dashboard: `/policies/compliance`
2. Add navigation link in sidebar/menu
3. Add breadcrumb support

**Acceptance Criteria:**
- ✅ Compliance Dashboard accessible via navigation
- ✅ Route works correctly
- ✅ Breadcrumbs display properly

---

### Phase 3.2: AI-Powered Summary Generation (Week 2-3)

**Goal:** Implement AI-powered summary generation for policy changes and compliance status

#### 3.2.1: Backend AI Summary Service

**File:** `dashboard-api/src/policies/services/ai-summary.service.ts` (NEW)

**Implementation:**

```typescript
import { Injectable } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { Policy } from '../entities/policy.entity';
import { GapAnalysis } from './gap-analysis.service';
import { ComplianceAnalysis } from './system-state-comparison.service';

export interface ExecutiveSummary {
  summary: string;
  keyMetrics: {
    policiesCreated: number;
    policiesModified: number;
    policiesDeleted: number;
    complianceScore: number;
    totalGaps: number;
    criticalGaps: number;
  };
  keyChanges: string[];
  impact: {
    resourcesAffected: number;
    applicationsAffected: number;
    estimatedEffort: string;
  };
  recommendations: string[];
}

export interface DetailedSummary {
  policyChanges: Array<{
    policyId: string;
    policyName: string;
    changeType: 'created' | 'modified' | 'deleted';
    changes: string[];
    affectedResources: string[];
    affectedApplications: string[];
    requiredActions: string[];
  }>;
  complianceStatus: {
    overallScore: number;
    policyScores: Array<{
      policyId: string;
      policyName: string;
      score: number;
      gaps: number;
    }>;
  };
  gapAnalysis: {
    totalGaps: number;
    gapsBySeverity: Record<string, number>;
    topGaps: Array<{
      id: string;
      title: string;
      severity: string;
      priority: number;
    }>;
  };
}

@Injectable()
export class AISummaryService {
  constructor(
    private readonly policiesService: PoliciesService,
  ) {}

  /**
   * Generate executive summary of policy changes
   */
  async generateExecutiveSummary(
    startDate: Date,
    endDate: Date,
  ): Promise<ExecutiveSummary> {
    // Get policies changed in date range
    const policies = await this.policiesService.findAll();
    const changedPolicies = this.filterByDateRange(policies, startDate, endDate);

    // Get compliance analysis
    const complianceAnalysis = await this.getComplianceAnalysis();

    // Generate summary using template + AI enhancement
    const summary = this.generateSummaryText(changedPolicies, complianceAnalysis);

    return {
      summary,
      keyMetrics: {
        policiesCreated: changedPolicies.filter(p => this.isNew(p, startDate)).length,
        policiesModified: changedPolicies.filter(p => !this.isNew(p, startDate)).length,
        policiesDeleted: 0, // Would need to track deletions
        complianceScore: complianceAnalysis.compliancePercentage,
        totalGaps: complianceAnalysis.gaps.length,
        criticalGaps: complianceAnalysis.summary.critical,
      },
      keyChanges: this.extractKeyChanges(changedPolicies),
      impact: this.calculateImpact(changedPolicies),
      recommendations: this.generateRecommendations(complianceAnalysis),
    };
  }

  /**
   * Generate detailed technical summary
   */
  async generateDetailedSummary(
    startDate: Date,
    endDate: Date,
  ): Promise<DetailedSummary> {
    const policies = await this.policiesService.findAll();
    const changedPolicies = this.filterByDateRange(policies, startDate, endDate);
    const complianceAnalysis = await this.getComplianceAnalysis();

    return {
      policyChanges: changedPolicies.map(policy => ({
        policyId: policy.id,
        policyName: policy.name,
        changeType: this.determineChangeType(policy, startDate),
        changes: this.extractPolicyChanges(policy),
        affectedResources: this.getAffectedResources(policy),
        affectedApplications: this.getAffectedApplications(policy),
        requiredActions: this.getRequiredActions(policy),
      })),
      complianceStatus: {
        overallScore: complianceAnalysis.compliancePercentage,
        policyScores: await this.getPolicyScores(),
      },
      gapAnalysis: {
        totalGaps: complianceAnalysis.gaps.length,
        gapsBySeverity: complianceAnalysis.summary,
        topGaps: complianceAnalysis.gaps
          .slice(0, 10)
          .map(gap => ({
            id: gap.id,
            title: gap.title,
            severity: gap.severity,
            priority: gap.priority,
          })),
      },
    };
  }

  /**
   * Generate compliance summary
   */
  async generateComplianceSummary(): Promise<string> {
    const complianceAnalysis = await this.getComplianceAnalysis();
    
    return this.formatComplianceSummary(complianceAnalysis);
  }

  // Helper methods...
  private filterByDateRange(policies: Policy[], start: Date, end: Date): Policy[] {
    return policies.filter(p => {
      const updated = new Date(p.lastUpdated);
      return updated >= start && updated <= end;
    });
  }

  private generateSummaryText(policies: Policy[], compliance: ComplianceAnalysis): string {
    // Template-based generation with AI enhancement
    // In production, this would call an LLM API
    const template = `
      Policy Changes Summary (${policies.length} policies):
      
      ${policies.length} policies were modified in this period.
      Overall compliance score: ${compliance.compliancePercentage}%
      ${compliance.gaps.length} compliance gaps detected.
      
      Key areas of focus:
      - ${compliance.summary.critical} critical gaps require immediate attention
      - ${compliance.summary.high} high-priority gaps should be addressed within 48 hours
    `;
    
    return template.trim();
  }

  // Additional helper methods...
}
```

**API Endpoints:**

```typescript
// In PoliciesController
@Get('summaries/executive')
async getExecutiveSummary(
  @Query('startDate') startDate: string,
  @Query('endDate') endDate: string,
): Promise<ExecutiveSummary> {
  const start = new Date(startDate);
  const end = new Date(endDate);
  return this.aiSummaryService.generateExecutiveSummary(start, end);
}

@Get('summaries/detailed')
async getDetailedSummary(
  @Query('startDate') startDate: string,
  @Query('endDate') endDate: string,
): Promise<DetailedSummary> {
  const start = new Date(startDate);
  const end = new Date(endDate);
  return this.aiSummaryService.generateDetailedSummary(start, end);
}

@Get('summaries/compliance')
async getComplianceSummary(): Promise<{ summary: string }> {
  const summary = await this.aiSummaryService.generateComplianceSummary();
  return { summary };
}
```

**Acceptance Criteria:**
- ✅ Executive summary generated correctly
- ✅ Detailed summary includes all required information
- ✅ Compliance summary is accurate
- ✅ API endpoints work correctly

#### 3.2.2: Frontend Summary Components

**Files:**
- `dashboard-frontend/src/components/policies/AISummaryView.vue` (NEW)
- `dashboard-frontend/src/components/policies/ExecutiveSummary.vue` (NEW)
- `dashboard-frontend/src/components/policies/DetailedSummary.vue` (NEW)

**Features:**
- Date range selector
- Executive summary display (non-technical language)
- Detailed summary display (technical breakdown)
- Export functionality (PDF, HTML, JSON)
- Summary customization options

**Implementation:**

```vue
<!-- AISummaryView.vue -->
<template>
  <div class="ai-summary-view">
    <div class="summary-header">
      <h2>Policy Change Summary</h2>
      <div class="date-range-selector">
        <input type="date" v-model="startDate" />
        <span>to</span>
        <input type="date" v-model="endDate" />
        <button @click="generateSummary" :disabled="loading" class="btn-primary">
          Generate Summary
        </button>
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <div class="loading-spinner"></div>
      <p>Generating summary...</p>
    </div>

    <div v-else-if="summary" class="summary-content">
      <div class="summary-tabs">
        <button @click="summaryType = 'executive'" :class="{ active: summaryType === 'executive' }">
          Executive Summary
        </button>
        <button @click="summaryType = 'detailed'" :class="{ active: summaryType === 'detailed' }">
          Detailed Summary
        </button>
      </div>

      <ExecutiveSummary v-if="summaryType === 'executive'" :summary="summary.executive" />
      <DetailedSummary v-if="summaryType === 'detailed'" :summary="summary.detailed" />

      <div class="summary-actions">
        <button @click="exportPDF" class="btn-secondary">Export PDF</button>
        <button @click="exportHTML" class="btn-secondary">Export HTML</button>
        <button @click="exportJSON" class="btn-secondary">Export JSON</button>
      </div>
    </div>
  </div>
</template>
```

**Acceptance Criteria:**
- ✅ Summary generation works correctly
- ✅ Both executive and detailed summaries display properly
- ✅ Export functionality works
- ✅ Date range selection works

---

### Phase 3.3: Enhanced User Experience (Week 3-4)

**Goal:** Improve workflows, navigation, and accessibility

#### 3.3.1: Policy Comparison Workflow Enhancement

**Enhancements:**
1. Add "Quick Compare" button to policy cards (compare with previous version)
2. Add "Compare with Template" option
3. Add "Compare Multiple Policies" feature
4. Improve diff viewer with better visualizations

**Acceptance Criteria:**
- ✅ Quick compare works from policy cards
- ✅ Template comparison works
- ✅ Multiple policy comparison works
- ✅ Diff viewer is more intuitive

#### 3.3.2: Remediation Workflow Enhancement

**Enhancements:**
1. Add "Start Remediation" button to gap cards
2. Add remediation progress tracking in policy detail view
3. Add notifications for gap status changes
4. Add bulk remediation actions

**Acceptance Criteria:**
- ✅ Remediation workflow is streamlined
- ✅ Progress tracking works
- ✅ Notifications appear correctly
- ✅ Bulk actions work

#### 3.3.3: Accessibility Improvements

**Enhancements:**
1. Add keyboard navigation for all components
2. Add ARIA labels for screen readers
3. Improve color contrast
4. Add focus management for modals

**Acceptance Criteria:**
- ✅ Keyboard navigation works throughout
- ✅ Screen reader compatibility verified
- ✅ Color contrast meets WCAG AA
- ✅ Focus management works correctly

---

## Data Models

### Summary Entity (New)

```typescript
interface PolicySummary {
  id: string;
  type: 'executive' | 'detailed' | 'compliance';
  generatedAt: Date;
  dateRange: {
    start: Date;
    end: Date;
  };
  content: ExecutiveSummary | DetailedSummary | string;
  exported: boolean;
  exportFormats: string[];
}
```

---

## UI/UX Design

### Compliance Dashboard Layout

**Layout:**
- Top: Overview cards (4 cards in a row)
- Middle: Gap Analysis View (full width)
- Bottom: Compliance Trends Chart (full width)
- Sidebar: Quick actions and filters

**Visual Design:**
- Color-coded compliance scores (green/yellow/red)
- Interactive charts
- Responsive grid layout

### Summary View Layout

**Layout:**
- Header: Title and date range selector
- Tabs: Executive / Detailed
- Content: Summary display
- Footer: Export actions

**Visual Design:**
- Clean, readable typography
- Highlighted key metrics
- Expandable sections for details

---

## Testing Requirements

### Unit Tests

**Backend:**
- `AISummaryService.spec.ts`
  - Executive summary generation
  - Detailed summary generation
  - Compliance summary generation
  - Date range filtering

**Frontend:**
- `AISummaryView.spec.ts`
  - Summary generation
  - Tab switching
  - Export functionality
- `ComplianceDashboard.spec.ts`
  - Dashboard loading
  - Overview cards display
  - Gap analysis integration

### Integration Tests

- End-to-end summary generation flow
- Compliance dashboard loading
- Gap analysis from dashboard
- Export functionality

### E2E Tests

- Generate executive summary
- Generate detailed summary
- View compliance dashboard
- Start remediation from gap analysis
- Export summary report

---

## Performance Considerations

### Backend Performance

- **Summary Generation:** < 5 seconds for date ranges < 30 days
- **Compliance Dashboard:** < 2 seconds for initial load
- **Gap Analysis:** < 3 seconds for single policy

**Optimization Strategies:**
- Cache summary results
- Async summary generation with progress updates
- Pagination for large gap lists
- Lazy loading of summary details

### Frontend Performance

- **Dashboard Load:** < 1 second
- **Summary Display:** < 500ms
- **Component Switching:** < 200ms

**Optimization Strategies:**
- Lazy load summary components
- Memoize computed properties
- Virtual scrolling for large lists
- Debounced search/filter

---

## Security Considerations

1. **Authorization:** Users can only view summaries for policies they have access to
2. **Data Exposure:** Ensure summaries don't expose sensitive policy details
3. **Audit Logging:** Log all summary generation actions
4. **Rate Limiting:** Limit summary generation API calls

---

## Migration & Rollout

### Phase 3.1 Rollout
1. Deploy enhanced policy detail modal
2. Deploy compliance dashboard
3. Add navigation links
4. Monitor usage and errors

### Phase 3.2 Rollout
1. Deploy AI summary service
2. Deploy summary UI components
3. Add summary generation to policy management
4. Monitor generation performance

### Phase 3.3 Rollout
1. Deploy UX enhancements incrementally
2. Gather user feedback
3. Iterate based on feedback

---

## Success Metrics

### Adoption Metrics
- 80% of users access gap analysis monthly
- 60% of users generate summaries monthly
- 50% reduction in time to identify compliance issues

### Quality Metrics
- Summary generation accuracy > 95%
- User satisfaction score > 4/5
- < 2% error rate in summary generation

### Performance Metrics
- Summary generation < 5 seconds (p95)
- Dashboard load < 1 second (p95)
- Component switching < 200ms (p95)

---

## Dependencies

### External Dependencies
- LLM API (for AI summary enhancement) - Optional, can use template-based initially
- Chart library (for trends visualization) - Recharts or Chart.js

### Internal Dependencies
- Phase 1 Policy Builder (complete ✅)
- Phase 2 Comparison Services (complete ✅)
- Phase 2 Frontend Components (need integration)

---

## Open Questions

1. **AI Integration:** Should we use an external LLM API or template-based generation?
   - **Recommendation:** Start with template-based, add LLM enhancement later

2. **Summary Caching:** How long should summaries be cached?
   - **Recommendation:** Cache for 1 hour, invalidate on policy changes

3. **Export Formats:** Which formats are most important?
   - **Recommendation:** PDF and JSON initially, add HTML later

4. **Real-time Updates:** Should compliance dashboard update in real-time?
   - **Recommendation:** Start with on-demand refresh, add real-time later

---

## Future Enhancements (Post-Phase 3)

1. **Advanced AI Features:**
   - Natural language policy queries
   - Policy recommendations
   - Automated policy optimization suggestions

2. **Enhanced Visualizations:**
   - Policy dependency graphs
   - Compliance heatmaps
   - Trend forecasting

3. **Collaboration Features:**
   - Share summaries with stakeholders
   - Comment on gaps
   - Assign remediation tasks

4. **Automation:**
   - Scheduled summary generation
   - Automated gap remediation
   - Policy change notifications

---

## Timeline Estimate

- **Phase 3.1:** 2 weeks
- **Phase 3.2:** 2 weeks
- **Phase 3.3:** 1 week
- **Testing & Polish:** 1 week

**Total:** ~6 weeks

---

## Risk Assessment

### Low Risk
- Component integration (follows existing patterns)
- Summary generation (template-based initially)

### Medium Risk
- AI summary quality (depends on LLM if used)
- Performance with large datasets

### High Risk
- None identified

**Mitigation:**
- Start with template-based summaries
- Add performance monitoring
- Iterate based on user feedback

---

## References

- **Phase 1 Validation:** `docs/development/POLICY_BUILDER_PHASE1_VALIDATION.md`
- **Phase 2 Plan:** `docs/development/POLICY_BUILDER_PHASE2_IMPLEMENTATION_PLAN.md`
- **PRD:** `docs/product/PRD.md` (Section 3.4: AI-Powered Summaries)
- **Template Plan:** `docs/development/TEMPLATE_MANAGEMENT_UI_PLAN.md`

---

**Document Status:** 📋 Planning  
**Last Updated:** January 31, 2026  
**Next Review:** After Phase 3.1 completion
