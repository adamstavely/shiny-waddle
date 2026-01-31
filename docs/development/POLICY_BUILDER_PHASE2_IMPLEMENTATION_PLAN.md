# Policy Builder Phase 2 Implementation Plan

**Date:** January 31, 2026  
**Status:** 📋 Planning  
**Priority:** High  
**Dependencies:** Phase 1 Complete ✅

---

## Executive Summary

Phase 2 focuses on **Diff and Comparison** capabilities, building upon the Phase 1 Policy Builder foundation. This phase enables users to compare policy versions, detect gaps between expected and actual policy enforcement, and identify data tag mismatches. The goal is to provide actionable insights that help users understand what needs to be fixed to achieve compliance.

---

## Phase 2 Goals

1. **Enhanced Version Diff View** - Visual, side-by-side comparison of policy versions with detailed highlighting
2. **Expected vs Actual State Comparison** - Compare defined policies against actual system enforcement
3. **Data Tag Comparison** - Identify missing, incorrect, or extra tags on resources
4. **Gap Analysis** - Comprehensive analysis of compliance gaps with prioritized remediation guidance
5. **Actionable Guidance** - Clear, step-by-step instructions on what needs to be fixed

---

## Current State Analysis

### Phase 1 Implementation ✅

**Frontend:**
- `PolicyVisualBuilder.vue` - Visual drag-and-drop policy builder
- `PolicyRuleBuilder.vue` - Rule/condition builder component
- `PolicyJSONEditor.vue` - Monaco-based JSON editor (read-only preview)
- `AccessControlPolicies.vue` - Main policy management view with integrated builder

**Backend:**
- `PoliciesController.compareVersions()` - Basic version comparison endpoint
- `PolicyVersioningService.compareVersions()` - Version comparison logic (basic implementation)
- Policy storage and versioning system
- Template management system

**Gaps Identified:**
- ❌ No frontend UI for version comparison
- ❌ Version comparison only compares metadata, not actual policy structure (rules/conditions)
- ❌ No expected vs actual state comparison service
- ❌ No data tag comparison functionality
- ❌ No gap analysis service
- ❌ No actionable guidance generation

---

## Architecture Overview

### Component Structure

```
Frontend Components:
├── PolicyDiffViewer.vue (New)
│   ├── VersionDiffPanel.vue (New)
│   ├── SystemStateDiffPanel.vue (New)
│   └── TagComparisonPanel.vue (New)
├── GapAnalysisView.vue (New)
│   ├── GapList.vue (New)
│   ├── GapDetail.vue (New)
│   └── RemediationGuide.vue (New)
└── PolicyComparisonModal.vue (New)
    └── ComparisonTabs.vue (New)
```

### Backend Services

```
Backend Services:
├── PolicyDiffService (New)
│   ├── comparePolicyStructure() - Deep policy comparison
│   ├── compareVersions() - Enhanced version comparison
│   └── generateDiffReport() - Generate diff reports
├── SystemStateComparisonService (New)
│   ├── compareExpectedVsActual() - Compare policy vs enforcement
│   ├── detectEnforcementGaps() - Find unenforced policies
│   └── analyzeCompliance() - Compliance analysis
├── DataTagComparisonService (New)
│   ├── compareTags() - Compare expected vs actual tags
│   ├── identifyMissingTags() - Find missing tags
│   ├── identifyIncorrectTags() - Find incorrect values
│   └── generateTagGuidance() - Generate update guidance
└── GapAnalysisService (New)
    ├── analyzeGaps() - Comprehensive gap analysis
    ├── prioritizeGaps() - Risk-based prioritization
    └── generateRemediationGuidance() - Actionable guidance
```

---

## Implementation Phases

### Phase 2.1: Enhanced Version Diff View (Week 1-2)

**Goal:** Build comprehensive version comparison UI with visual diff highlighting

#### Backend Enhancements

**File:** `dashboard-api/src/policies/services/policy-diff.service.ts` (New)

```typescript
@Injectable()
export class PolicyDiffService {
  /**
   * Deep comparison of policy structure (rules, conditions, effects)
   */
  comparePolicyStructure(
    policy1: Policy,
    policy2: Policy
  ): PolicyStructureDiff {
    // Compare:
    // - Rules (added, removed, modified)
    // - Conditions within rules
    // - Effects
    // - Metadata (name, description, status)
  }

  /**
   * Enhanced version comparison with structure diff
   */
  compareVersions(
    policy: Policy,
    version1: string,
    version2: string
  ): EnhancedVersionComparison {
    // Get policy snapshots for each version
    // Compare structure using comparePolicyStructure
    // Return detailed diff with line-by-line changes
  }

  /**
   * Generate diff report with visual markers
   */
  generateDiffReport(comparison: EnhancedVersionComparison): DiffReport {
    // Format diff for UI display
    // Include line numbers, change types, context
  }
}
```

**Interfaces:**

```typescript
interface PolicyStructureDiff {
  rules: {
    added: Rule[];
    removed: Rule[];
    modified: Array<{
      ruleId: string;
      changes: RuleChange[];
    }>;
  };
  conditions: {
    added: Condition[];
    removed: Condition[];
    modified: Array<{
      conditionId: string;
      changes: ConditionChange[];
    }>;
  };
  metadata: {
    changed: Array<{
      field: string;
      oldValue: any;
      newValue: any;
    }>;
  };
}

interface EnhancedVersionComparison extends VersionComparison {
  structureDiff: PolicyStructureDiff;
  visualDiff: VisualDiffMarker[];
}

interface VisualDiffMarker {
  type: 'added' | 'removed' | 'modified';
  path: string; // JSON path to changed element
  lineNumber?: number;
  oldValue?: any;
  newValue?: any;
  context?: string; // Surrounding context
}
```

**API Endpoints:**

```typescript
// Enhanced version comparison
GET /api/policies/:id/compare/:version1/:version2
Response: EnhancedVersionComparison

// Compare any two policies
POST /api/policies/compare
Body: { policyId1: string, policyId2: string }
Response: PolicyStructureDiff
```

#### Frontend Components

**File:** `dashboard-frontend/src/components/policies/PolicyDiffViewer.vue` (New)

**Features:**
- Side-by-side JSON diff view
- Unified diff view option
- Visual highlighting (green=added, red=removed, yellow=modified)
- Expand/collapse sections
- Line-by-line comparison
- Change summary panel
- Filter by change type
- Search within diff

**File:** `dashboard-frontend/src/components/policies/VersionDiffPanel.vue` (New)

**Features:**
- Version selector dropdowns
- Diff visualization
- Change summary statistics
- Impact analysis display

**Integration Points:**
- Add "Compare Versions" button to policy detail view
- Add "Compare" action to policy list
- Integrate into `AccessControlPolicies.vue`

**Acceptance Criteria:**
- ✅ Can select two versions to compare
- ✅ Visual diff shows all changes with color coding
- ✅ Can expand/collapse sections
- ✅ Change summary displays accurate counts
- ✅ JSON diff is accurate and readable
- ✅ Performance: Diff generation < 1 second

---

### Phase 2.2: Expected vs Actual State Comparison (Week 2-3)

**Goal:** Compare defined policies against actual system enforcement state

#### Backend Service

**File:** `dashboard-api/src/policies/services/system-state-comparison.service.ts` (New)

```typescript
@Injectable()
export class SystemStateComparisonService {
  constructor(
    private readonly policiesService: PoliciesService,
    private readonly testsService: TestsService,
    // Inject application/enforcement services as needed
  ) {}

  /**
   * Compare expected policy vs actual enforcement
   */
  async compareExpectedVsActual(
    policyId: string
  ): Promise<SystemStateComparison> {
    // 1. Get policy definition
    // 2. Query actual enforcement state (from tests, applications, etc.)
    // 3. Compare and identify gaps
    // 4. Return comparison result
  }

  /**
   * Detect policies not enforced in system
   */
  async detectEnforcementGaps(
    policyIds?: string[]
  ): Promise<EnforcementGap[]> {
    // Find policies that are defined but not enforced
    // Check test results, application configs, etc.
  }

  /**
   * Analyze compliance status
   */
  async analyzeCompliance(
    applicationId?: string
  ): Promise<ComplianceAnalysis> {
    // Overall compliance analysis
    // Percentage of policies enforced
    // List of gaps
  }
}
```

**Interfaces:**

```typescript
interface SystemStateComparison {
  policyId: string;
  policyName: string;
  expected: {
    rules: Rule[];
    conditions: Condition[];
    effect: 'allow' | 'deny';
  };
  actual: {
    enforced: boolean;
    enforcementLocation?: string; // Application, service, etc.
    rules?: Rule[]; // Actual enforced rules
    conditions?: Condition[]; // Actual enforced conditions
    effect?: 'allow' | 'deny';
  };
  gaps: EnforcementGap[];
  compliance: {
    isCompliant: boolean;
    compliancePercentage: number;
    missingRules: Rule[];
    missingConditions: Condition[];
  };
}

interface EnforcementGap {
  type: 'policy-not-enforced' | 'rule-missing' | 'condition-missing' | 'effect-mismatch';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  expected: any;
  actual: any;
  location?: string; // Where it should be enforced
  remediation: RemediationStep[];
}
```

**API Endpoints:**

```typescript
// Compare policy with system state
GET /api/policies/:id/system-state-comparison
Response: SystemStateComparison

// Detect all enforcement gaps
GET /api/policies/enforcement-gaps
Query: ?applicationId, ?policyId
Response: EnforcementGap[]

// Compliance analysis
GET /api/policies/compliance-analysis
Query: ?applicationId
Response: ComplianceAnalysis
```

#### Frontend Components

**File:** `dashboard-frontend/src/components/policies/SystemStateDiffPanel.vue` (New)

**Features:**
- Expected vs Actual side-by-side view
- Gap list with severity indicators
- Compliance score display
- Filter gaps by type/severity
- Link to remediation guides

**Integration:**
- Add "Compare with System State" button to policy detail view
- Add compliance badge to policy cards
- Add compliance dashboard view

**Acceptance Criteria:**
- ✅ Can compare policy with system state
- ✅ Gaps are accurately identified
- ✅ Compliance score is calculated correctly
- ✅ Gaps are prioritized by severity
- ✅ Links to remediation guides work

---

### Phase 2.3: Data Tag Comparison (Week 3-4)

**Goal:** Compare expected data tags (from policies) vs actual tags on resources

#### Backend Service

**File:** `dashboard-api/src/policies/services/data-tag-comparison.service.ts` (New)

```typescript
@Injectable()
export class DataTagComparisonService {
  constructor(
    private readonly policiesService: PoliciesService,
    // Inject resource service when available
  ) {}

  /**
   * Compare expected tags vs actual tags for a resource
   */
  async compareTags(
    resourceId: string,
    policyId?: string
  ): Promise<TagComparison> {
    // 1. Get expected tags from policies that reference this resource
    // 2. Get actual tags from resource
    // 3. Compare and identify differences
  }

  /**
   * Identify missing tags
   */
  identifyMissingTags(
    expected: Record<string, string>,
    actual: Record<string, string>
  ): string[] {
    // Find tags in expected but not in actual
  }

  /**
   * Identify incorrect tag values
   */
  identifyIncorrectTags(
    expected: Record<string, string>,
    actual: Record<string, string>
  ): Array<{ key: string; expected: string; actual: string }> {
    // Find tags with wrong values
  }

  /**
   * Generate tag update guidance
   */
  generateTagGuidance(
    comparison: TagComparison
  ): TagUpdateGuidance {
    // Step-by-step instructions for updating tags
  }
}
```

**Interfaces:**

```typescript
interface TagComparison {
  resourceId: string;
  resourceName: string;
  expectedTags: Record<string, string>; // From policies
  actualTags: Record<string, string>; // From resource
  missingTags: string[];
  incorrectTags: Array<{
    key: string;
    expected: string;
    actual: string;
  }>;
  extraTags: string[]; // Tags in actual but not expected
  compliance: {
    isCompliant: boolean;
    missingCount: number;
    incorrectCount: number;
  };
}

interface TagUpdateGuidance {
  resourceId: string;
  actions: Array<{
    type: 'add' | 'update' | 'remove';
    tag: string;
    value: string;
    reason: string; // Which policy requires this tag
    steps: string[]; // How to update
  }>;
  estimatedTime: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
}
```

**API Endpoints:**

```typescript
// Compare tags for a resource
GET /api/policies/tags/compare/:resourceId
Query: ?policyId
Response: TagComparison

// Compare tags for all resources
GET /api/policies/tags/compare-all
Query: ?policyId, ?applicationId
Response: TagComparison[]

// Get tag update guidance
GET /api/policies/tags/guidance/:resourceId
Response: TagUpdateGuidance
```

#### Frontend Components

**File:** `dashboard-frontend/src/components/policies/TagComparisonPanel.vue` (New)

**Features:**
- Expected vs Actual tags side-by-side
- Visual indicators (✓ compliant, ✗ missing, ⚠ incorrect)
- Tag update form inline
- Bulk tag update capability
- Link to resource management
- Tag update guidance display

**Integration:**
- Add "Compare Tags" button to resource detail view
- Add tag compliance badge to resource cards
- Add tag comparison to policy detail view

**Acceptance Criteria:**
- ✅ Can compare tags for any resource
- ✅ Missing tags are clearly identified
- ✅ Incorrect tags show expected vs actual
- ✅ Tag update guidance is actionable
- ✅ Can update tags directly from comparison view

---

### Phase 2.4: Gap Analysis & Remediation Guidance (Week 4-5)

**Goal:** Comprehensive gap analysis with prioritized remediation guidance

#### Backend Service

**File:** `dashboard-api/src/policies/services/gap-analysis.service.ts` (New)

```typescript
@Injectable()
export class GapAnalysisService {
  constructor(
    private readonly systemStateService: SystemStateComparisonService,
    private readonly tagComparisonService: DataTagComparisonService,
    private readonly policiesService: PoliciesService,
  ) {}

  /**
   * Comprehensive gap analysis
   */
  async analyzeGaps(
    policyId?: string,
    applicationId?: string
  ): Promise<GapAnalysis> {
    // 1. Get enforcement gaps
    // 2. Get tag comparison gaps
    // 3. Prioritize by risk/impact
    // 4. Generate remediation guidance
  }

  /**
   * Prioritize gaps by risk
   */
  prioritizeGaps(gaps: Gap[]): PrioritizedGap[] {
    // Risk scoring algorithm
    // Consider: severity, impact, affected resources, compliance requirements
  }

  /**
   * Generate actionable remediation guidance
   */
  generateRemediationGuidance(
    gap: Gap
  ): RemediationGuidance {
    // Step-by-step instructions
    // Links to relevant interfaces
    // Code examples if applicable
  }
}
```

**Interfaces:**

```typescript
interface GapAnalysis {
  policyId?: string;
  applicationId?: string;
  gaps: PrioritizedGap[];
  summary: {
    totalGaps: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    complianceScore: number; // 0-100
  };
  recommendations: string[];
}

interface PrioritizedGap {
  id: string;
  type: 'enforcement' | 'tag' | 'attribute' | 'policy';
  severity: 'low' | 'medium' | 'high' | 'critical';
  priority: number; // 1-10, higher = more urgent
  title: string;
  description: string;
  affectedResources: string[];
  affectedApplications: string[];
  remediation: RemediationGuidance;
  estimatedEffort: string; // e.g., "30 minutes", "2 hours"
}

interface RemediationGuidance {
  steps: RemediationStep[];
  estimatedTime: string;
  requiredPermissions: string[];
  links: Array<{
    label: string;
    url: string;
    type: 'internal' | 'external' | 'documentation';
  }>;
  codeExamples?: Array<{
    language: string;
    code: string;
    description: string;
  }>;
}

interface RemediationStep {
  order: number;
  action: string;
  description: string;
  expectedOutcome: string;
  verification?: string; // How to verify completion
}
```

**API Endpoints:**

```typescript
// Comprehensive gap analysis
GET /api/policies/gap-analysis
Query: ?policyId, ?applicationId
Response: GapAnalysis

// Get remediation guidance for a gap
GET /api/policies/gaps/:gapId/remediation
Response: RemediationGuidance

// Track remediation progress
POST /api/policies/gaps/:gapId/progress
Body: { step: number, completed: boolean, notes?: string }
```

#### Frontend Components

**File:** `dashboard-frontend/src/components/policies/GapAnalysisView.vue` (New)

**Features:**
- Gap list with priority sorting
- Filter by type, severity, status
- Gap detail view with remediation guide
- Progress tracking
- Compliance score visualization
- Export gap report

**File:** `dashboard-frontend/src/components/policies/RemediationGuide.vue` (New)

**Features:**
- Step-by-step remediation instructions
- Progress checklist
- Code examples display
- Links to relevant interfaces
- Mark steps as complete
- Notes/comments per step

**Integration:**
- Add "Gap Analysis" tab to policy detail view
- Add "Compliance Gaps" dashboard view
- Add gap badges to policy cards

**Acceptance Criteria:**
- ✅ All gaps are identified and prioritized
- ✅ Remediation guidance is actionable
- ✅ Progress tracking works
- ✅ Compliance score is accurate
- ✅ Can export gap reports

---

## Data Models

### Enhanced Policy Entity

```typescript
interface Policy {
  // ... existing fields ...
  gapAnalysis?: {
    lastAnalyzed: Date;
    complianceScore: number;
    gaps: string[]; // Gap IDs
  };
  systemStateComparison?: {
    lastCompared: Date;
    isCompliant: boolean;
    enforcementGaps: string[];
  };
}
```

### Gap Entity (New)

```typescript
interface Gap {
  id: string;
  policyId: string;
  type: 'enforcement' | 'tag' | 'attribute' | 'policy';
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'in-progress' | 'resolved' | 'accepted';
  createdAt: Date;
  resolvedAt?: Date;
  resolvedBy?: string;
  remediation: RemediationGuidance;
  progress: {
    currentStep: number;
    completedSteps: number[];
    notes: Record<number, string>;
  };
}
```

---

## UI/UX Design

### Version Diff View

**Layout:**
- Split view: Left (Version 1) | Right (Version 2)
- Unified view option
- Summary panel on top
- Change filters on sidebar

**Visual Design:**
- Green highlight: Added content
- Red highlight: Removed content
- Yellow highlight: Modified content
- Line numbers
- Expand/collapse sections
- Smooth scrolling synchronization

### Gap Analysis View

**Layout:**
- List view with cards
- Priority badges (Critical, High, Medium, Low)
- Filter sidebar
- Detail panel (slide-out or modal)

**Visual Design:**
- Color-coded severity badges
- Progress bars for remediation
- Compliance score gauge
- Interactive remediation checklist

### Tag Comparison View

**Layout:**
- Side-by-side: Expected | Actual
- Inline edit capability
- Bulk actions toolbar
- Guidance panel

**Visual Design:**
- Checkmarks for compliant tags
- Warning icons for incorrect tags
- Plus icons for missing tags
- Edit buttons inline

---

## Testing Requirements

### Unit Tests

**Backend:**
- `PolicyDiffService.spec.ts`
  - Policy structure comparison
  - Version comparison accuracy
  - Diff report generation
- `SystemStateComparisonService.spec.ts`
  - Expected vs actual comparison
  - Enforcement gap detection
  - Compliance analysis
- `DataTagComparisonService.spec.ts`
  - Tag comparison logic
  - Missing tag identification
  - Incorrect tag detection
- `GapAnalysisService.spec.ts`
  - Gap prioritization algorithm
  - Remediation guidance generation
  - Progress tracking

**Frontend:**
- `PolicyDiffViewer.spec.ts`
  - Diff rendering
  - Change highlighting
  - Filter functionality
- `GapAnalysisView.spec.ts`
  - Gap list display
  - Filtering and sorting
  - Progress tracking

### Integration Tests

- End-to-end version comparison flow
- System state comparison with mock enforcement data
- Tag comparison with resource updates
- Gap analysis and remediation tracking

### E2E Tests

- Compare two policy versions
- Compare policy with system state
- Compare tags for a resource
- View gap analysis
- Complete a remediation step

---

## Performance Considerations

### Backend Performance

- **Diff Generation:** < 1 second for policies with < 100 rules
- **System State Comparison:** < 5 seconds for single policy
- **Tag Comparison:** < 2 seconds for single resource
- **Gap Analysis:** < 10 seconds for application-level analysis

**Optimization Strategies:**
- Cache policy snapshots for version comparison
- Batch tag comparisons
- Async gap analysis with progress updates
- Pagination for large gap lists

### Frontend Performance

- **Diff Rendering:** < 2 seconds for large policies
- **Gap List Loading:** < 1 second for < 100 gaps
- **Tag Comparison:** < 500ms for single resource

**Optimization Strategies:**
- Virtual scrolling for large diff views
- Lazy loading of gap details
- Debounced search/filter
- Memoized computed properties

---

## Security Considerations

1. **Authorization:** Users can only compare policies they have access to
2. **Data Exposure:** Ensure tag comparison doesn't expose sensitive resource data
3. **Audit Logging:** Log all comparison and gap analysis actions
4. **Input Validation:** Validate all comparison inputs
5. **Rate Limiting:** Limit comparison API calls to prevent abuse

---

## Migration & Rollout

### Phase 2.1 Rollout
1. Deploy backend diff service
2. Deploy frontend diff viewer
3. Add "Compare Versions" to policy detail view
4. Monitor performance and errors

### Phase 2.2 Rollout
1. Deploy system state comparison service
2. Deploy system state diff panel
3. Add compliance badges
4. Monitor enforcement gap detection accuracy

### Phase 2.3 Rollout
1. Deploy tag comparison service
2. Deploy tag comparison panel
3. Integrate with resource management
4. Monitor tag update success rate

### Phase 2.4 Rollout
1. Deploy gap analysis service
2. Deploy gap analysis view
3. Add remediation tracking
4. Monitor remediation completion rates

---

## Success Metrics

### Adoption Metrics
- 80% of policies have been compared at least once
- 60% of users use gap analysis monthly
- 50% reduction in manual compliance checking

### Quality Metrics
- 95%+ accuracy in gap detection
- < 5% false positive rate
- 100% of gaps have actionable remediation guidance

### Performance Metrics
- Diff generation < 1 second (p95)
- Gap analysis < 10 seconds (p95)
- Tag comparison < 2 seconds (p95)

### Business Impact
- 70% reduction in time to identify compliance gaps
- 50% reduction in time to remediate gaps
- 30% improvement in overall compliance score

---

## Dependencies

### External Dependencies
- Resource management service (for tag updates)
- Application/enforcement state service (for system state comparison)
- Test results service (for compliance validation)

### Internal Dependencies
- Phase 1 Policy Builder (complete ✅)
- Policy versioning system (exists)
- Resource management UI (exists, may need enhancements)

---

## Open Questions

1. **Policy Snapshots:** Should we store full policy snapshots for each version, or reconstruct from version history?
   - **Recommendation:** Store snapshots for performance, reconstruct if missing

2. **Enforcement State Source:** Where does actual enforcement state come from?
   - **Recommendation:** Start with test results, expand to application configs later

3. **Tag Update Permissions:** Who can update resource tags?
   - **Recommendation:** Resource owners + data stewards

4. **Gap Resolution Workflow:** Should gaps require approval to mark as resolved?
   - **Recommendation:** Yes for critical/high severity gaps

5. **Real-time Updates:** Should gap analysis update in real-time as policies/resources change?
   - **Recommendation:** Start with on-demand, add real-time later

---

## Future Enhancements (Post-Phase 2)

1. **Automated Remediation:** Auto-fix simple gaps (e.g., add missing tags)
2. **Gap Prediction:** Predict gaps before they occur
3. **Compliance Trends:** Historical compliance trend analysis
4. **Bulk Operations:** Bulk tag updates, bulk gap resolution
5. **Integration:** CI/CD integration to block deployments with gaps
6. **Notifications:** Alert users when gaps are detected
7. **Reporting:** Scheduled compliance reports

---

## Timeline Estimate

- **Phase 2.1:** 2 weeks
- **Phase 2.2:** 2 weeks
- **Phase 2.3:** 2 weeks
- **Phase 2.4:** 2 weeks
- **Testing & Polish:** 1 week

**Total:** ~9 weeks

---

## Risk Assessment

### Low Risk
- Version diff UI (follows existing patterns)
- Tag comparison (straightforward logic)

### Medium Risk
- System state comparison (depends on enforcement state source)
- Gap prioritization algorithm (may need tuning)

### High Risk
- Performance with large policies (need optimization)
- Accuracy of enforcement gap detection (depends on data quality)

**Mitigation:**
- Start with small datasets
- Iterate on algorithms based on feedback
- Add performance monitoring
- Provide fallback to manual review

---

## References

- **Phase 1 Validation:** `docs/development/POLICY_BUILDER_PHASE1_VALIDATION.md`
- **PRD:** `docs/product/PRD.md` (Section 3.2: Diff and Comparison Features)
- **Template Plan:** `docs/development/TEMPLATE_MANAGEMENT_UI_PLAN.md`
- **Policy Builder PRD Plan:** `/Users/adamstavely/.cursor/plans/access_policy_builder_prd_b5d9c707.plan.md`

---

**Document Status:** 📋 Planning  
**Last Updated:** January 31, 2026  
**Next Review:** After Phase 2.1 completion
