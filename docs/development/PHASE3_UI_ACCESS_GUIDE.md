# Phase 3 UI Access Guide

This document explains where to find and access all Phase 3 features in the UI.

## 🎯 Quick Access Summary

### 1. Compliance Dashboard
**Location:** `/policies/compliance`

**How to Access:**
- **Via Sidebar:** Click "Access Control" in the sidebar, then click "Compliance Dashboard" in the drawer menu
- **Direct URL:** Navigate to `/policies/compliance`
- **From Policies Overview:** Click "Compliance Dashboard" button on the policies overview page

**Features:**
- Overview cards showing Total Policies, Compliance Score, Total Gaps, Critical Gaps
- Integrated Gap Analysis View
- Compliance Trends (placeholder for chart)
- Export Report functionality

### 2. Policy Detail Modal - New Tabs

**How to Access:**
1. Go to **Access Control Policies** (`/policies/access-control`)
2. Click on any policy card to open the detail modal
3. You'll see new tabs at the top:
   - **Versions** - View version history and compare versions
   - **System State** - Compare expected vs actual policy enforcement
   - **Gap Analysis** - View compliance gaps for this policy
   - **Tags** - Compare data tags (requires resource ID)

**Quick Actions from Policy Cards:**
- **"View Gaps"** button - Opens policy detail modal directly to Gap Analysis tab
- **"Compare State"** button - Opens policy detail modal directly to System State tab
- **"Compare"** button - Opens version comparison modal

### 3. AI Summary View

**Location:** Currently not directly linked in navigation (can be accessed via direct route or added to menu)

**How to Access:**
- **Direct URL:** Create a route or add a button/link to access `/policies/summaries` (if route is added)
- **Component:** `AISummaryView.vue` can be integrated into any view

**Features:**
- Date range selector for policy changes
- Executive Summary (high-level, non-technical)
- Detailed Summary (technical breakdown)
- Export options (PDF placeholder, HTML, JSON)

## 📍 Detailed Navigation Paths

### Compliance Dashboard Path
```
Sidebar → Access Control → (Drawer opens) → Compliance Dashboard
```

### Policy Detail Modal Path
```
Sidebar → Access Control → (Click any policy card) → Modal opens with tabs:
  - Basic Info (default)
  - Rules/Conditions
  - Visual Builder
  - Code
  - Preview
  - Versions ⭐ NEW
  - System State ⭐ NEW
  - Gap Analysis ⭐ NEW
  - Tags ⭐ NEW
```

### Quick Actions from Policy Cards
When viewing the Access Control Policies page, each policy card has action buttons:
- **Edit** - Opens edit modal
- **Versions** - Navigates to version history
- **Compare** - Opens version comparison modal
- **View Gaps** ⭐ NEW - Opens policy detail modal to Gap Analysis tab
- **Compare State** ⭐ NEW - Opens policy detail modal to System State tab
- **Test** - Navigate to test page
- **Delete** - Delete policy

## 🔧 Adding AI Summary to Navigation (Optional)

To make the AI Summary view easily accessible, you can:

1. **Add to Drawer Menu:**
   Edit `dashboard-frontend/src/components/Drawer.vue` and add:
   ```vue
   <a
     href="/policies/summaries"
     @click.prevent="handleNavClick('/policies/summaries')"
     :class="['drawer-item', isActive('/policies/summaries') ? 'drawer-item-active' : '']"
   >
     <BarChart3 class="item-icon" />
     <span>Policy Summaries</span>
   </a>
   ```

2. **Add Route:**
   Edit `dashboard-frontend/src/router/index.ts` and add:
   ```typescript
   {
     path: '/policies/summaries',
     name: 'PolicySummaries',
     component: () => import('../components/policies/AISummaryView.vue'),
   }
   ```

3. **Add to Policies Overview:**
   Add a button in `PoliciesOverview.vue`:
   ```vue
   <button @click="navigateTo('/policies/summaries')" class="btn-secondary">
     View Summaries
   </button>
   ```

## 📊 Component Locations

### Backend Services
- `dashboard-api/src/policies/services/ai-summary.service.ts` - AI Summary generation
- All Phase 2 services are already integrated

### Frontend Components
- `dashboard-frontend/src/views/policies/ComplianceDashboard.vue` - Main compliance dashboard
- `dashboard-frontend/src/components/policies/OverviewCard.vue` - Dashboard metric cards
- `dashboard-frontend/src/components/policies/AISummaryView.vue` - AI Summary main view
- `dashboard-frontend/src/components/policies/ExecutiveSummary.vue` - Executive summary display
- `dashboard-frontend/src/components/policies/DetailedSummary.vue` - Detailed summary display
- `dashboard-frontend/src/components/policies/GapAnalysisView.vue` - Gap analysis (Phase 2, now integrated)
- `dashboard-frontend/src/components/policies/SystemStateDiffPanel.vue` - System state comparison (Phase 2, now integrated)
- `dashboard-frontend/src/components/policies/TagComparisonPanel.vue` - Tag comparison (Phase 2, now integrated)

## 🎨 Visual Indicators

Look for these icons/indicators:
- **Shield icon** - Compliance-related features
- **AlertTriangle icon** - Gap analysis
- **Gauge icon** - Compliance scores
- **GitCompare icon** - Version comparison
- **BarChart3 icon** - Summaries and reports

## 🚀 Testing Checklist

To verify Phase 3 features are working:

1. ✅ Navigate to Compliance Dashboard via sidebar
2. ✅ Open a policy and see new tabs (Versions, System State, Gap Analysis, Tags)
3. ✅ Click "View Gaps" button on a policy card
4. ✅ Click "Compare State" button on a policy card
5. ✅ Access AI Summary view (if route is added)
6. ✅ Export reports from Compliance Dashboard
7. ✅ View version history in Versions tab
8. ✅ Compare system state in System State tab

## 📝 Notes

- The Compliance Dashboard loads data from `/api/policies/compliance-analysis`
- AI Summary requires date range selection
- Tag Comparison requires a resource ID to be entered
- All Phase 2 components are now integrated and accessible from the policy detail modal
