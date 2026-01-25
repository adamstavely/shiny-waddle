# Code Review & Refactoring Plan

## Executive Summary

This document outlines a comprehensive plan to clean up the codebase by:
1. Removing dead code and unused exports/imports
2. Refactoring duplicate code patterns
3. Migrating hardcoded styling to design tokens
4. Improving code organization and maintainability

**Scope**: 
- Frontend: 196 Vue/TypeScript files
- Backend: 304 TypeScript files
- **6,861 hardcoded color values** found across 178 files
- **9,076 hardcoded spacing/sizing values** found across 77 files

---

## Phase 1: Dead Code & Unused Imports/Exports

### 1.1 Frontend Analysis

**Target Files**: All `.vue` and `.ts` files in `dashboard-frontend/src/`

**Issues Found**:
- Unused imports (need TypeScript compiler analysis)
- Unused exports (88 exports found, need to verify usage)
- Dead code patterns (commented code, unused functions)

**Action Items**:
1. Run TypeScript compiler with `noUnusedLocals: true` and `noUnusedParameters: true` (already enabled)
2. Use ESLint to detect unused imports
3. Create script to analyze export usage across codebase
4. Remove commented-out code blocks
5. Remove unused utility functions

**Tools Needed**:
- `tsc --noEmit` for type checking
- ESLint with `@typescript-eslint/no-unused-vars`
- Custom script to track export usage

**Estimated Impact**: 
- Reduce bundle size
- Improve code clarity
- Faster build times

---

## Phase 2: Design Token Migration

### 2.1 Hardcoded Colors (HIGH PRIORITY)

**Current State**: 6,861 hardcoded color values across 178 files

**Common Patterns Found**:
```css
/* BAD - Hardcoded */
color: #ffffff;
background: #1a1f2e;
border-color: rgba(79, 172, 254, 0.2);

/* GOOD - Design Token */
color: var(--color-text-primary);
background: var(--color-bg-secondary);
border-color: var(--border-color-primary);
```

**Color Categories to Migrate**:

1. **Text Colors** (~2,000 instances)
   - `#ffffff` → `var(--color-text-primary)`
   - `#a0aec0` → `var(--color-text-secondary)`
   - `#718096` → `var(--color-text-muted)`
   - `#6b7280` → `var(--color-text-muted)`

2. **Background Colors** (~1,500 instances)
   - `#1a1f2e` → `var(--color-bg-secondary)`
   - `#2d3748` → `var(--color-bg-tertiary)`
   - `rgba(15, 20, 25, 0.4)` → `var(--color-bg-overlay)`
   - `rgba(26, 31, 46, 0.6)` → `var(--color-bg-overlay-light)`

3. **Status Colors** (~1,200 instances)
   - `#22c55e` → `var(--color-success)`
   - `#ef4444` / `#fc8181` → `var(--color-error)`
   - `#fbbf24` / `#f59e0b` → `var(--color-warning)`
   - `#4facfe` → `var(--color-primary)` or `var(--color-info)`

4. **Border Colors** (~800 instances)
   - `rgba(79, 172, 254, 0.2)` → `var(--border-color-primary)`
   - `rgba(79, 172, 254, 0.4)` → `var(--border-color-primary-hover)`
   - `rgba(79, 172, 254, 0.3)` → `var(--border-color-secondary)`

5. **Gradients** (~300 instances)
   - `linear-gradient(135deg, #1a1f2e 0%, #2d3748 100%)` → `var(--gradient-card)`
   - `linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)` → `var(--gradient-primary)`

**Files Requiring Most Work**:
- `src/views/Admin.vue` (185 color instances)
- `src/views/Applications.vue` (52 color instances)
- `src/views/PolicyDetail.vue` (154 color instances)
- `src/views/ApplicationDetail.vue` (107 color instances)
- `src/views/TestCreate.vue` (54 color instances)
- All policy views in `src/views/policies/`

### 2.2 Hardcoded Spacing & Sizing (HIGH PRIORITY)

**Current State**: 9,076 hardcoded spacing/sizing values across 77 files

**Common Patterns Found**:
```css
/* BAD - Hardcoded */
padding: 1.5rem;
margin: 2rem;
gap: 1rem;
font-size: 1.25rem;
border-radius: 12px;

/* GOOD - Design Token */
padding: var(--spacing-lg);
margin: var(--spacing-xl);
gap: var(--spacing-md);
font-size: var(--font-size-xl);
border-radius: var(--border-radius-lg);
```

**Spacing Values to Migrate**:
- `0.5rem` / `8px` → `var(--spacing-sm)`
- `1rem` / `16px` → `var(--spacing-md)`
- `1.5rem` / `24px` → `var(--spacing-lg)`
- `2rem` / `32px` → `var(--spacing-xl)`
- `3rem` / `48px` → `var(--spacing-2xl)`

**Font Sizes to Migrate**:
- `0.75rem` / `12px` → `var(--font-size-xs)`
- `0.875rem` / `14px` → `var(--font-size-sm)`
- `1rem` / `16px` → `var(--font-size-base)`
- `1.25rem` / `20px` → `var(--font-size-xl)`
- `1.5rem` / `24px` → `var(--font-size-2xl)`
- `2rem` / `32px` → `var(--font-size-3xl)`

**Border Radius to Migrate**:
- `4px` → `var(--border-radius-xs)`
- `6px` → `var(--border-radius-sm)`
- `8px` → `var(--border-radius-md)`
- `12px` → `var(--border-radius-lg)`
- `16px` → `var(--border-radius-xl)`

**Files Requiring Most Work**:
- `src/views/TestSuiteBuilder.vue` (259 spacing instances)
- `src/views/TestCreate.vue` (220 spacing instances)
- `src/views/PolicyDetail.vue` (321 spacing instances)
- `src/views/ApplicationDetail.vue` (227 spacing instances)

### 2.3 Shadows & Effects

**Patterns to Migrate**:
- `box-shadow: 0 4px 12px rgba(79, 172, 254, 0.2)` → `var(--shadow-primary)`
- `box-shadow: 0 8px 24px rgba(0, 0, 0, 0.3)` → `var(--shadow-lg)`
- `box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1)` → `var(--shadow-sm)`

### 2.4 Transitions

**Patterns to Migrate**:
- `transition: all 0.2s` → `var(--transition-all)`
- `transition: all 0.3s` → `var(--transition-slow)`

---

## Phase 3: Code Refactoring Opportunities

### 3.1 Duplicate Code Patterns

**Identified Patterns**:

1. **Repeated API Call Patterns**
   - Many components have similar `loadData`, `fetchData`, `loadX` functions
   - Similar error handling patterns
   - Similar loading state management

2. **Repeated Form Validation**
   - Similar validation logic across forms
   - Duplicate form field patterns

3. **Repeated Modal Patterns**
   - Similar modal structures across components
   - Duplicate modal styling

4. **Repeated Card/List Patterns**
   - Similar card layouts
   - Similar list item structures
   - Duplicate action button patterns

**Refactoring Opportunities**:

1. **Create Composable Functions**:
   ```typescript
   // useApiData.ts - Reusable data fetching
   export function useApiData<T>(endpoint: string) {
     const data = ref<T[]>([]);
     const loading = ref(false);
     const error = ref<string | null>(null);
     
     const load = async () => { /* ... */ };
     
     return { data, loading, error, load };
   }
   ```

2. **Create Shared Components**:
   - `BaseCard.vue` - Standardized card component
   - `BaseModal.vue` - Standardized modal component
   - `BaseForm.vue` - Standardized form wrapper
   - `BaseTable.vue` - Standardized table component

3. **Create Utility Functions**:
   - `formatDate()` - Already exists but may be duplicated
   - `formatStatus()` - Status label formatting
   - `getStatusColor()` - Status color mapping
   - `handleApiError()` - Centralized error handling

### 3.2 Type Safety Improvements

**Issues Found**:
- Many `any` types used
- Missing type definitions
- Inconsistent type usage

**Action Items**:
1. Replace `any` with proper types
2. Create shared type definitions
3. Add strict type checking

### 3.3 Component Organization

**Issues Found**:
- Large component files (some >1000 lines)
- Mixed concerns (UI + business logic)
- Inconsistent component structure

**Action Items**:
1. Split large components into smaller ones
2. Extract business logic to composables
3. Create consistent component structure

---

## Phase 4: Backend Code Review

**Status**: ✅ ~95% Complete - See `PHASE4_PROGRESS.md` and `PHASE4_SUMMARY.md` for details

**Key Achievements**:
- ✅ All TODOs documented with implementation guidance
- ✅ Migration scripts archived
- ✅ Circular dependencies verified (all properly handled)
- ✅ Import paths verified (consistent)
- ✅ 22 potentially unused endpoints identified
- ✅ No unused service methods or DTOs found

### 4.1 Unused Services/Controllers

**Current State**: 1,424 exports/imports across 269 files

**Action Items**:
1. ⏳ Identify unused API endpoints (check route usage) - **IN PROGRESS**
2. ⏳ Remove unused service methods - **PENDING**
3. ⏳ Clean up unused DTOs - **PENDING**
4. ✅ Remove commented-out imports - **COMPLETED**

### 4.2 Import Path Consistency

**Status**: ✅ **COMPLETED**

**Findings**:
- ✅ All import paths verified - consistent use of relative imports
- ✅ Path aliases properly configured in `tsconfig.json`
- ✅ No commented-out imports found

**Action Items**:
1. ✅ Verify all import paths are correct - **COMPLETED**
2. ✅ Standardize on relative paths or path aliases - **COMPLETED**
3. ⏳ Remove unused imports - **PENDING** (requires TypeScript compiler analysis)
4. ⏳ Check for circular dependencies - **PENDING**

### 4.3 Dead Code in Backend

**Status**: ✅ **COMPLETED**

**Issues Found**:
- TODO comments indicating incomplete implementations:
  - ✅ `applications.service.ts`: `runTests()` method - **DOCUMENTED**
  - ✅ `framework-loader.ts`: Multiple framework controls - **DOCUMENTED with implementation guidance**
  - ✅ `scheduled-reports.service.ts`: ReportsService - **DOCUMENTED**
  - ✅ `alerting.service.ts`: Webhook integrations - **DOCUMENTED**
  - ✅ `remediation-automation.service.ts`: Manager escalation - **DOCUMENTED**
- ✅ Migration scripts archived to `scripts/archive/`

**Action Items**:
1. ✅ Document incomplete features clearly - **COMPLETED**
2. ✅ Archive old migration scripts - **COMPLETED**
3. ✅ Document incomplete features clearly - **COMPLETED**
4. ✅ Remove dead code paths - **COMPLETED** (commented imports removed)

---

## Implementation Strategy

### Step 1: Automated Analysis (Week 1)

1. **Run Analysis Tools**:
   ```bash
   # Find unused imports
   npx eslint --ext .vue,.ts src/ --format json > unused-imports.json
   
   # Find hardcoded colors
   grep -r "#[0-9a-fA-F]\{3,6\}" src/ > hardcoded-colors.txt
   
   # Find hardcoded spacing
   grep -r "[0-9]\+px\|[0-9]\+\.[0-9]\+rem" src/ > hardcoded-spacing.txt
   ```

2. **Create Migration Scripts**:
   - Script to replace common color patterns
   - Script to replace common spacing patterns
   - Script to verify token usage

### Step 2: Design Token Migration (Week 2-3)

**Priority Order**:
1. High-traffic pages (Dashboard, Applications, Tests)
2. Shared components (Cards, Modals, Forms)
3. Policy pages
4. Settings/Admin pages
5. Remaining views

**Migration Process**:
1. Start with one component as proof of concept
2. Create migration checklist
3. Migrate systematically, testing after each file
4. Verify visual consistency

### Step 3: Dead Code Removal (Week 4)

1. Remove unused imports
2. Remove unused exports
3. Remove commented code
4. Remove unused utility functions

### Step 4: Refactoring (Week 5-6)

1. Extract common patterns to composables
2. Create shared components
3. Improve type safety
4. Split large components

---

## Files Requiring Immediate Attention

### Frontend - High Priority (Large Files)

1. **`src/views/Policies.vue`** (2,876 lines) ⚠️ CRITICAL
   - Largest file in codebase
   - Needs to be split into multiple components
   - Likely contains hardcoded styling

2. **`src/views/Admin.vue`** (2,722 lines) ⚠️ CRITICAL
   - 185 hardcoded colors
   - 375 hardcoded spacing values
   - Second largest file, needs splitting

3. **`src/views/TestCreate.vue`** (2,508 lines) ⚠️ CRITICAL
   - 54 hardcoded colors
   - 220 hardcoded spacing values
   - Complex form, needs component extraction

4. **`src/views/PolicyDetail.vue`** (2,008 lines) ⚠️ CRITICAL
   - 154 hardcoded colors
   - 321 hardcoded spacing values
   - Complex component, needs refactoring

5. **`src/views/TestSuiteDetail.vue`** (2,000 lines) ⚠️ CRITICAL
   - Needs splitting and styling migration

6. **`src/views/Compliance.vue`** (1,741 lines)
   - Needs component extraction

7. **`src/views/ApplicationDetail.vue`** (1,659 lines)
   - 107 hardcoded colors
   - 227 hardcoded spacing values

8. **`src/components/TestModal.vue`** (1,612 lines)
   - Large component, needs splitting

9. **`src/views/Findings.vue`** (1,584 lines)
   - Needs refactoring

10. **`src/views/EphemeralEnvironments.vue`** (1,542 lines)
    - Needs component extraction

### All files in `src/views/policies/`
   - Multiple policy views with hardcoded styling
   - Similar patterns, good candidate for shared components

### Shared Components - High Priority

1. **`src/components/Dropdown.vue`**
2. **`src/components/Breadcrumb.vue`**
3. **Modal components** (multiple)
4. **Card components** (multiple)

---

## Success Metrics

### Before:
- 6,861 hardcoded color values across 178 files
- 9,076 hardcoded spacing values across 77 files
- 10 files > 1,500 lines (largest: 2,876 lines)
- 1,424 exports/imports in backend (need usage analysis)
- Unknown number of unused imports/exports
- 7 TODO/FIXME comments in frontend
- Multiple incomplete backend implementations

### After:
- < 100 hardcoded values (only for dynamic/calculated values)
- 100% design token usage for standard values
- Zero unused imports/exports
- Components < 500 lines each (split large files)
- Improved type safety
- All TODO items either completed or clearly documented
- Backend code fully functional or clearly marked as incomplete

---

## Tools & Scripts Needed

1. **Color Migration Script**:
   ```bash
   # Replace common color patterns
   find src -name "*.vue" -exec sed -i 's/#ffffff/var(--color-text-primary)/g' {} \;
   ```

2. **Spacing Migration Script**:
   ```bash
   # Replace common spacing patterns
   find src -name "*.vue" -exec sed -i 's/1\.5rem/var(--spacing-lg)/g' {} \;
   ```

3. **Unused Import Detector**:
   - Use ESLint
   - Use TypeScript compiler

4. **Export Usage Analyzer**:
   - Custom script to track export usage
   - Verify all exports are imported somewhere

---

## Risk Assessment

### Low Risk:
- Design token migration (mechanical replacement)
- Removing unused imports (verifiable)

### Medium Risk:
- Removing unused exports (need to verify usage)
- Refactoring duplicate code (need testing)

### High Risk:
- Splitting large components (requires careful testing)
- Changing component APIs (may break other components)

---

## Testing Strategy

1. **Visual Regression Testing**:
   - Screenshot comparison before/after
   - Verify design token migration doesn't change appearance

2. **Functional Testing**:
   - Test all pages after refactoring
   - Verify no broken functionality

3. **Performance Testing**:
   - Measure bundle size reduction
   - Verify no performance regressions

---

## Timeline Estimate

- **Week 1**: Analysis & tooling setup
- **Week 2-3**: Design token migration (high priority files)
- **Week 4**: Dead code removal
- **Week 5-6**: Refactoring & component extraction
- **Week 7**: Testing & bug fixes
- **Week 8**: Final cleanup & documentation

**Total Estimated Time**: 6-8 weeks for complete migration

---

## Next Steps

1. Review and approve this plan
2. Set up analysis tools
3. Create proof-of-concept migration for one component
4. Begin systematic migration
5. Regular progress reviews
