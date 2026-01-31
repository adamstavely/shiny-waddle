# Template Management UI Implementation Plan

**Date:** January 31, 2026  
**Status:** 📋 Planning  
**Priority:** Medium (Enhancement)

---

## Executive Summary

This document outlines the implementation plan for a dedicated Template Management UI that allows users to view, create, edit, delete, and manage policy templates. The core template functionality (selection and application) is already implemented in the Visual Builder. This plan adds a comprehensive management interface.

---

## Goals

1. **Centralized Template Management**: Provide a dedicated interface for managing all policy templates
2. **Template CRUD Operations**: Full create, read, update, delete capabilities
3. **Template Discovery**: Easy browsing and filtering of templates
4. **Template Preview**: Visual preview of template structure before use
5. **Template Analytics**: Usage statistics and popularity metrics
6. **Template Sharing**: Ability to create and share custom templates

---

## User Stories

### As a Data Steward
- I want to browse available templates by category and type
- I want to preview a template's structure before using it
- I want to create custom templates from existing policies
- I want to edit templates to keep them up-to-date
- I want to see which templates are most commonly used

### As an Administrator
- I want to manage all templates in one place
- I want to delete unused or outdated templates
- I want to organize templates with tags and categories
- I want to see template usage analytics

---

## Architecture Overview

### Frontend Components

```
TemplateManagementView.vue (Main View)
├── TemplateList.vue (Grid/List View)
│   ├── TemplateCard.vue (Individual Template Card)
│   └── TemplateFilters.vue (Search, Category, Type filters)
├── TemplateDetailModal.vue (View/Edit Template)
│   ├── TemplateInfo.vue (Basic Info Tab)
│   ├── TemplatePreview.vue (Policy Structure Preview)
│   ├── TemplateEditor.vue (Edit Template Content)
│   └── TemplateUsage.vue (Usage Statistics)
└── CreateTemplateModal.vue (Create New Template)
    ├── TemplateForm.vue (Form Fields)
    └── PolicyVisualBuilder.vue (Reuse existing builder)
```

### Backend Integration

- **Existing Endpoints** (Already implemented):
  - `GET /api/policies/templates` - List templates
  - `GET /api/policies/templates/:id` - Get template
  - `POST /api/policies/templates` - Create template
  - `PATCH /api/policies/templates/:id` - Update template
  - `DELETE /api/policies/templates/:id` - Delete template
  - `POST /api/policies/templates/:id/use` - Track usage

- **Additional Endpoints** (May be needed):
  - `GET /api/policies/templates/:id/usage` - Detailed usage stats
  - `POST /api/policies/templates/:id/duplicate` - Duplicate template
  - `POST /api/policies/templates/:id/export` - Export template as JSON

---

## Implementation Phases

### Phase 1: Core List View (Week 1)

**Goal**: Display templates in a browsable grid/list view

**Components to Create:**
1. `TemplateManagementView.vue` - Main view component
2. `TemplateCard.vue` - Template card component
3. `TemplateFilters.vue` - Filter component

**Features:**
- Grid/list view of all templates
- Search by name/description
- Filter by:
  - Policy Type (RBAC/ABAC)
  - Category (department, role, resource, compliance, custom)
  - Tags
- Sort by:
  - Name (A-Z, Z-A)
  - Usage Count (Most/Least Used)
  - Created Date (Newest/Oldest)
  - Updated Date

**UI Pattern**: Similar to `AccessControlPolicies.vue` with grid layout

**Acceptance Criteria:**
- ✅ All templates displayed in grid
- ✅ Search filters templates in real-time
- ✅ Category/type filters work correctly
- ✅ Sorting works for all options
- ✅ Empty state shown when no templates match filters

---

### Phase 2: Template Detail View (Week 1-2)

**Goal**: View detailed information about a template

**Components to Create:**
1. `TemplateDetailModal.vue` - Modal wrapper
2. `TemplateInfo.vue` - Basic information display
3. `TemplatePreview.vue` - Policy structure preview
4. `TemplateUsage.vue` - Usage statistics

**Features:**
- View template metadata:
  - Name, description, category, tags
  - Policy type, version
  - Created/updated dates
  - Usage count
- Preview template structure:
  - Visual representation of rules/conditions
  - JSON preview
  - Policy visualization (reuse `PolicyVisualization.vue`)
- Usage statistics:
  - Total usage count
  - Recent usage (last 10 uses)
  - Usage trend (if historical data available)

**Actions Available:**
- Edit template
- Duplicate template
- Delete template
- Use template (navigate to policy creation with template pre-selected)
- Export template as JSON

**UI Pattern**: Modal with tabs (Info, Preview, Usage)

**Acceptance Criteria:**
- ✅ Template details display correctly
- ✅ Preview shows accurate policy structure
- ✅ Usage statistics are accurate
- ✅ All actions work correctly

---

### Phase 3: Template Creation (Week 2)

**Goal**: Create new templates from scratch or from existing policies

**Components to Create:**
1. `CreateTemplateModal.vue` - Modal wrapper
2. `TemplateForm.vue` - Form for template metadata
3. `TemplateBuilder.vue` - Policy builder (reuse Visual Builder)

**Features:**
- Create from scratch:
  - Enter template metadata (name, description, category, tags)
  - Build policy structure using Visual Builder
  - Preview before saving
- Create from existing policy:
  - Select an existing policy
  - Convert to template
  - Edit metadata and structure
- Validation:
  - Required fields validation
  - Policy structure validation
  - Duplicate name checking

**UI Pattern**: Multi-step modal (Metadata → Builder → Preview)

**Acceptance Criteria:**
- ✅ Can create template from scratch
- ✅ Can create template from existing policy
- ✅ Validation prevents invalid templates
- ✅ Template saved successfully

---

### Phase 4: Template Editing (Week 2-3)

**Goal**: Edit existing templates

**Components to Create:**
1. `EditTemplateModal.vue` - Edit modal (reuse CreateTemplateModal with edit mode)
2. `TemplateEditor.vue` - Editor component

**Features:**
- Edit template metadata
- Edit policy structure:
  - Use Visual Builder
  - Use Code editor
  - Use Rules/Conditions form
- Version tracking:
  - Track changes
  - Show change history
- Impact analysis:
  - Show which policies use this template
  - Warn about breaking changes

**UI Pattern**: Similar to policy editing modal with tabs

**Acceptance Criteria:**
- ✅ Can edit all template fields
- ✅ Changes are saved correctly
- ✅ Version history is tracked
- ✅ Impact analysis works

---

### Phase 5: Advanced Features (Week 3)

**Goal**: Additional management features

**Features:**
- Bulk operations:
  - Delete multiple templates
  - Tag multiple templates
  - Export multiple templates
- Template organization:
  - Custom categories
  - Tag management
  - Template folders/collections (future)
- Analytics dashboard:
  - Most used templates
  - Template usage trends
  - Category distribution
- Import/Export:
  - Import templates from JSON
  - Export templates to JSON
  - Bulk import/export

**Components to Create:**
1. `TemplateAnalytics.vue` - Analytics dashboard
2. `BulkActionsBar.vue` - Bulk operations toolbar
3. `ImportExportModal.vue` - Import/export interface

**Acceptance Criteria:**
- ✅ Bulk operations work correctly
- ✅ Analytics display accurate data
- ✅ Import/export functions correctly

---

## Component Specifications

### TemplateManagementView.vue

**Location**: `dashboard-frontend/src/views/policies/TemplateManagementView.vue`

**Props**: None

**State:**
- `templates: PolicyTemplate[]`
- `filteredTemplates: PolicyTemplate[]`
- `loading: boolean`
- `error: string | null`
- `searchQuery: string`
- `filterCategory: string`
- `filterType: PolicyType | null`
- `sortBy: string`
- `sortOrder: 'asc' | 'desc'`
- `selectedTemplate: PolicyTemplate | null`
- `showCreateModal: boolean`
- `showDetailModal: boolean`
- `showEditModal: boolean`

**Methods:**
- `loadTemplates()`
- `filterTemplates()`
- `sortTemplates()`
- `deleteTemplate(id)`
- `duplicateTemplate(id)`
- `exportTemplate(id)`

**UI Structure:**
```vue
<template>
  <div class="template-management-page">
    <Breadcrumb />
    <PageHeader>
      <Title>Policy Templates</Title>
      <CreateButton />
    </PageHeader>
    
    <TemplateFilters />
    
    <TemplateGrid>
      <TemplateCard v-for="template in filteredTemplates" />
    </TemplateGrid>
    
    <CreateTemplateModal />
    <TemplateDetailModal />
    <EditTemplateModal />
  </div>
</template>
```

---

### TemplateCard.vue

**Location**: `dashboard-frontend/src/components/policies/TemplateCard.vue`

**Props:**
- `template: PolicyTemplate`

**Events:**
- `@click` - View details
- `@use` - Use template
- `@edit` - Edit template
- `@delete` - Delete template
- `@duplicate` - Duplicate template

**Display:**
- Template name
- Description (truncated)
- Category badge
- Policy type badge (RBAC/ABAC)
- Tags
- Usage count
- Created/updated dates
- Quick actions (Use, Edit, Delete)

**UI Pattern**: Similar to policy cards in `AccessControlPolicies.vue`

---

### TemplateDetailModal.vue

**Location**: `dashboard-frontend/src/components/policies/TemplateDetailModal.vue`

**Props:**
- `show: boolean`
- `template: PolicyTemplate | null`

**Events:**
- `@close`
- `@edit`
- `@delete`
- `@use`
- `@duplicate`

**Tabs:**
1. **Info** - Basic information
2. **Preview** - Policy structure preview
3. **Usage** - Usage statistics

**UI Pattern**: Modal with tabs, similar to policy detail modals

---

### CreateTemplateModal.vue

**Location**: `dashboard-frontend/src/components/policies/CreateTemplateModal.vue`

**Props:**
- `show: boolean`
- `sourcePolicy?: Policy` - Optional: create from existing policy

**Events:**
- `@close`
- `@save`

**Steps:**
1. **Metadata** - Name, description, category, tags
2. **Builder** - Use Visual Builder or Code editor
3. **Preview** - Review before saving

**UI Pattern**: Multi-step wizard modal

---

## Routing

**Route**: `/policies/templates`

**Navigation**:
- Add link to sidebar/navigation menu
- Add link from Access Control Policies page
- Breadcrumb: Home → Policies → Templates

**Route Configuration**:
```typescript
{
  path: '/policies/templates',
  name: 'PolicyTemplates',
  component: () => import('@/views/policies/TemplateManagementView.vue'),
  meta: {
    title: 'Policy Templates',
    requiresAuth: true,
  }
}
```

---

## Data Flow

### Loading Templates
```
User navigates to /policies/templates
  ↓
TemplateManagementView mounted
  ↓
loadTemplates() called
  ↓
GET /api/policies/templates
  ↓
Templates displayed in grid
```

### Creating Template
```
User clicks "Create Template"
  ↓
CreateTemplateModal opens
  ↓
User fills metadata → Builder → Preview
  ↓
User clicks "Save"
  ↓
POST /api/policies/templates
  ↓
Template created, modal closes, list refreshes
```

### Using Template
```
User clicks "Use" on template card
  ↓
POST /api/policies/templates/:id/use (track usage)
  ↓
Navigate to /policies/access-control
  ↓
Open Create Policy modal
  ↓
Pre-select template in Visual Builder
  ↓
Template applied to policy form
```

---

## Styling Guidelines

**Design System Compliance:**
- Use CSS design tokens (`var(--color-*)`, `var(--spacing-*)`)
- Follow dark mode theme
- Consistent with existing policy management UI
- Responsive grid layout

**Component Styling:**
- Template cards: Similar to policy cards
- Filters: Match existing filter components
- Modals: Match existing modal patterns
- Buttons: Use existing button styles

---

## Testing Requirements

### Unit Tests
- `TemplateManagementView.spec.ts`
  - Template loading
  - Filtering and sorting
  - Search functionality
  - Template actions (delete, duplicate, export)

- `TemplateCard.spec.ts`
  - Card rendering
  - Action button clicks
  - Template display

- `TemplateDetailModal.spec.ts`
  - Modal display
  - Tab switching
  - Data display

- `CreateTemplateModal.spec.ts`
  - Form validation
  - Multi-step navigation
  - Template creation

### Integration Tests
- Template CRUD operations
- Template usage tracking
- Template import/export
- Template filtering and search

### E2E Tests
- Complete template creation flow
- Template editing flow
- Template deletion with confirmation
- Template usage from list
- Template search and filtering

---

## Accessibility Requirements

- **Keyboard Navigation**: All actions accessible via keyboard
- **Screen Reader Support**: Proper ARIA labels
- **Focus Management**: Focus trapped in modals
- **Color Contrast**: Meets WCAG AA standards
- **Error Messages**: Clear, descriptive error messages

---

## Performance Considerations

- **Lazy Loading**: Load templates on demand
- **Pagination**: If template count > 50, implement pagination
- **Virtual Scrolling**: For large lists
- **Caching**: Cache template list for faster navigation
- **Debouncing**: Debounce search input (300ms)

---

## Security Considerations

- **Authorization**: Check user permissions before allowing template management
- **Input Validation**: Validate all template inputs
- **XSS Prevention**: Sanitize template content
- **CSRF Protection**: Use CSRF tokens for mutations

---

## Future Enhancements

1. **Template Versioning**: Track template versions
2. **Template Collections**: Group templates into collections
3. **Template Marketplace**: Share templates across organizations
4. **Template Validation**: Validate templates against schema
5. **Template Testing**: Test templates before saving
6. **Template Comments**: Add comments/notes to templates
7. **Template Ratings**: Rate templates for quality
8. **Template Recommendations**: Suggest templates based on usage

---

## Dependencies

### Frontend
- Vue 3 (already installed)
- Vue Router (already installed)
- Axios (already installed)
- Monaco Editor (already installed)
- Existing components:
  - `PolicyVisualBuilder.vue`
  - `PolicyRuleBuilder.vue`
  - `PolicyJSONEditor.vue`
  - `PolicyVisualization.vue`
  - `Dropdown.vue`
  - `Breadcrumb.vue`

### Backend
- All endpoints already implemented
- No additional dependencies needed

---

## Implementation Checklist

### Phase 1: Core List View
- [ ] Create `TemplateManagementView.vue`
- [ ] Create `TemplateCard.vue`
- [ ] Create `TemplateFilters.vue`
- [ ] Add route configuration
- [ ] Add navigation links
- [ ] Implement search functionality
- [ ] Implement filtering
- [ ] Implement sorting
- [ ] Add empty state
- [ ] Add loading state
- [ ] Add error handling
- [ ] Write unit tests
- [ ] Write E2E tests

### Phase 2: Template Detail View
- [ ] Create `TemplateDetailModal.vue`
- [ ] Create `TemplateInfo.vue`
- [ ] Create `TemplatePreview.vue`
- [ ] Create `TemplateUsage.vue`
- [ ] Implement template detail display
- [ ] Implement usage statistics
- [ ] Add action buttons
- [ ] Write unit tests
- [ ] Write E2E tests

### Phase 3: Template Creation
- [ ] Create `CreateTemplateModal.vue`
- [ ] Create `TemplateForm.vue`
- [ ] Integrate Visual Builder
- [ ] Implement form validation
- [ ] Implement "Create from Policy" flow
- [ ] Add preview step
- [ ] Write unit tests
- [ ] Write E2E tests

### Phase 4: Template Editing
- [ ] Create `EditTemplateModal.vue`
- [ ] Create `TemplateEditor.vue`
- [ ] Implement edit functionality
- [ ] Add version tracking
- [ ] Add impact analysis
- [ ] Write unit tests
- [ ] Write E2E tests

### Phase 5: Advanced Features
- [ ] Create `TemplateAnalytics.vue`
- [ ] Create `BulkActionsBar.vue`
- [ ] Create `ImportExportModal.vue`
- [ ] Implement bulk operations
- [ ] Implement analytics
- [ ] Implement import/export
- [ ] Write unit tests
- [ ] Write E2E tests

---

## Success Metrics

- **Usability**: Users can create templates in < 2 minutes
- **Performance**: Template list loads in < 1 second
- **Adoption**: 80% of new policies use templates
- **Quality**: < 5% of templates are deleted due to errors
- **Satisfaction**: User satisfaction score > 4/5

---

## Timeline Estimate

- **Phase 1**: 3-5 days
- **Phase 2**: 3-5 days
- **Phase 3**: 5-7 days
- **Phase 4**: 5-7 days
- **Phase 5**: 7-10 days

**Total**: ~4-6 weeks for complete implementation

---

## Risk Assessment

### Low Risk
- Component creation (follows existing patterns)
- API integration (endpoints already exist)
- Styling (uses existing design system)

### Medium Risk
- Template creation from existing policy (requires careful data transformation)
- Impact analysis (requires tracking template usage in policies)

### High Risk
- None identified

---

## Open Questions

1. Should templates be versioned separately from policies?
2. Should there be template approval workflow?
3. Should templates be shareable across organizations?
4. Should there be template categories beyond the current 5?
5. Should templates support template variables/placeholders?

---

## References

- **Existing Implementation**: `AccessControlPolicies.vue`
- **Template Service**: `dashboard-api/src/policies/services/policy-templates.service.ts`
- **Template DTOs**: `dashboard-api/src/policies/dto/create-template.dto.ts`
- **Validation Plan**: `docs/development/POLICY_BUILDER_PHASE1_VALIDATION.md`

---

**Document Status**: 📋 Planning  
**Last Updated**: January 31, 2026  
**Next Review**: After Phase 1 completion
