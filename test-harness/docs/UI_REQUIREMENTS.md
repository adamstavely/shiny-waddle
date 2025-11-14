# UI Requirements for Validator Registry System

This document outlines what needs to be added to the TestOrchestrator dashboard UI to support the new validator registry system and extensibility features.

## 1. Admin Page - Validators Tab

**Location:** `/admin` → New "Validators" tab

**Purpose:** Manage registered validators, view their metadata, and configure them.

### Features Needed:

#### Validator List View
- Display all registered validators in a card/list format
- Show for each validator:
  - Name and description
  - Version
  - Test type(s) it handles
  - Status (enabled/disabled)
  - Last run timestamp
  - Number of tests executed
  - Success/failure rate

#### Validator Details Modal
- View full validator metadata
- See required/optional configuration
- View example configuration
- See dependencies and tags
- View supported checks/rules (for configuration validators)

#### Validator Management
- Enable/disable validators
- View validator configuration (masked credentials)
- Edit validator configuration
- Remove validators (with confirmation)
- Test validator connection/configuration

#### Add Validator
- Form to register new validators
- Select validator type (if multiple available)
- Configure connection settings
- Upload/configure rules/policies
- Validate configuration before saving

### UI Components Needed:
- `ValidatorsList.vue` - List of validators
- `ValidatorCard.vue` - Individual validator card
- `ValidatorDetailModal.vue` - View/edit validator details
- `AddValidatorModal.vue` - Form to add new validator

---

## 2. Tests Page Enhancements

**Location:** `/tests` - Enhance existing page

### Features Needed:

#### Validator Filter
- Filter tests by validator type
- Filter by specific validator
- Show which validators ran for each test

#### Test Result Details
- Show which validator executed each test
- Display validator-specific details in test results
- Link to validator documentation/metadata

#### Validator Status Indicators
- Show validator health/status
- Indicate if validator is enabled/disabled
- Show last successful run

### UI Components Needed:
- Update `Tests.vue` to include validator filter
- Add validator badges to test results
- Add validator info tooltip/modal

---

## 3. Dashboard Enhancements

**Location:** `/dashboard` - Enhance existing page

### Features Needed:

#### Validator Breakdown
- Show compliance scores by validator type
- Pie/bar chart showing distribution of tests by validator
- Validator health status widget

#### Validator Metrics
- Number of active validators
- Tests executed per validator
- Success rate per validator
- Recent validator activity

### UI Components Needed:
- `ValidatorMetrics.vue` - Widget showing validator statistics
- Update `Dashboard.vue` to include validator breakdown

---

## 4. Configuration Validation Page (New)

**Location:** `/configuration-validation` - New page

**Purpose:** Manage and view configuration validation results (Salesforce, Elastic Cloud, etc.)

### Features Needed:

#### Validation Targets List
- List of configured validation targets (Salesforce orgs, Elastic Cloud tenants, etc.)
- Status of each target (healthy, warnings, errors)
- Last validation run
- Next scheduled run

#### Validation Rules Management
- View rules for each target
- Create/edit/delete validation rules
- Enable/disable rules
- Set rule severity levels

#### Validation Results
- View results from last validation run
- Filter by target, rule, severity
- Drill down into specific rule violations
- View historical validation results

#### Add Validation Target
- Form to add new validation target (Salesforce, Elastic Cloud, etc.)
- Configure connection settings
- Select/create validation rules
- Test connection before saving

### UI Components Needed:
- `ConfigurationValidation.vue` - Main page component
- `ValidationTargetCard.vue` - Card for each target
- `ValidationRulesList.vue` - List of rules for a target
- `ValidationResultsTable.vue` - Table of validation results
- `AddValidationTargetModal.vue` - Form to add target
- `ValidationRuleEditor.vue` - Editor for validation rules

---

## 5. Policy Detail Page Enhancement

**Location:** `/policies/:id` - Enhance existing page

### Features Needed:

#### Validator Information
- Show which validators use this policy
- Link to validator details
- Show policy usage across validators

---

## 6. Reports Page Enhancement

**Location:** `/reports` - Enhance existing page

### Features Needed:

#### Validator-Specific Reports
- Filter reports by validator
- Generate reports for specific validators
- Include validator metadata in reports

---

## 7. API Endpoints Needed

To support the UI, we'll need these backend API endpoints:

### Validators API
- `GET /api/validators` - List all validators
- `GET /api/validators/:id` - Get validator details
- `POST /api/validators` - Register new validator
- `PATCH /api/validators/:id` - Update validator configuration
- `DELETE /api/validators/:id` - Remove validator
- `POST /api/validators/:id/test` - Test validator connection
- `PATCH /api/validators/:id/enable` - Enable validator
- `PATCH /api/validators/:id/disable` - Disable validator

### Configuration Validation API
- `GET /api/validation-targets` - List validation targets
- `GET /api/validation-targets/:id` - Get target details
- `POST /api/validation-targets` - Create validation target
- `PATCH /api/validation-targets/:id` - Update target
- `DELETE /api/validation-targets/:id` - Delete target
- `POST /api/validation-targets/:id/validate` - Run validation
- `GET /api/validation-targets/:id/results` - Get validation results
- `GET /api/validation-targets/:id/rules` - Get rules for target
- `POST /api/validation-targets/:id/rules` - Add rule
- `PATCH /api/validation-rules/:id` - Update rule
- `DELETE /api/validation-rules/:id` - Delete rule

---

## 8. Navigation Updates

### Sidebar
- Add "Configuration Validation" menu item (if new page is created)
- Or add it as a sub-item under "Tests" or "Admin"

### Admin Page Tabs
- Add "Validators" tab to existing Admin page tabs

---

## 9. Priority Implementation Order

### Phase 1: Core Validator Management (High Priority)
1. ✅ Validators tab in Admin page
2. ✅ Validator list view
3. ✅ Validator details modal
4. ✅ Enable/disable validators
5. ✅ Basic API endpoints

### Phase 2: Integration (Medium Priority)
1. ✅ Tests page validator filter
2. ✅ Dashboard validator metrics
3. ✅ Validator info in test results

### Phase 3: Configuration Validation (Lower Priority)
1. ✅ Configuration Validation page
2. ✅ Validation targets management
3. ✅ Validation rules editor
4. ✅ Validation results viewer

---

## 10. Design Considerations

### Visual Indicators
- Use badges/icons to show validator status
- Color code by validator type
- Show health indicators (green/yellow/red)

### User Experience
- Make it easy to discover available validators
- Provide clear error messages for configuration issues
- Show helpful tooltips and documentation links
- Provide example configurations

### Security
- Mask sensitive credentials in UI
- Require confirmation for destructive actions
- Show audit log of validator changes
- Support role-based access control

### Performance
- Lazy load validator details
- Cache validator metadata
- Paginate validator lists if many validators
- Use optimistic UI updates

---

## 11. Example UI Mockups

### Validators Tab (Admin Page)
```
┌─────────────────────────────────────────────────┐
│ Validators                                      │
├─────────────────────────────────────────────────┤
│ [+ Add Validator]                               │
│                                                 │
│ ┌─────────────────┐ ┌─────────────────┐       │
│ │ Access Control  │ │ Salesforce      │       │
│ │ ✅ Enabled      │ │ ✅ Enabled      │       │
│ │ v1.0.0          │ │ v1.0.0          │       │
│ │ 1,247 tests     │ │ 45 validations  │       │
│ │ 98% success     │ │ 100% success    │       │
│ │ [View Details]  │ │ [View Details]  │       │
│ └─────────────────┘ └─────────────────┘       │
│                                                 │
│ ┌─────────────────┐                            │
│ │ Elastic Cloud   │                            │
│ │ ⚠️ Disabled      │                            │
│ │ v1.0.0          │                            │
│ │ 0 validations   │                            │
│ │ [View Details]  │                            │
│ └─────────────────┘                            │
└─────────────────────────────────────────────────┘
```

### Configuration Validation Page
```
┌─────────────────────────────────────────────────┐
│ Configuration Validation                        │
├─────────────────────────────────────────────────┤
│ [+ Add Validation Target]                       │
│                                                 │
│ ┌─────────────────────────────────────────────┐ │
│ │ Salesforce Org: production                 │ │
│ │ ✅ Healthy | Last run: 2 hours ago         │ │
│ │ Rules: 12 | Passed: 11 | Failed: 1        │ │
│ │ [View Results] [Edit Rules] [Run Now]     │ │
│ └─────────────────────────────────────────────┘ │
│                                                 │
│ ┌─────────────────────────────────────────────┐ │
│ │ Elastic Cloud: us-east-1                    │ │
│ │ ⚠️ Warnings | Last run: 1 day ago           │ │
│ │ Rules: 8 | Passed: 7 | Failed: 1           │ │
│ │ [View Results] [Edit Rules] [Run Now]      │ │
│ └─────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

---

## Summary

The main UI additions needed are:

1. **Validators Tab in Admin** - Manage validators (highest priority)
2. **Tests Page Enhancements** - Show validator info in tests
3. **Dashboard Enhancements** - Validator metrics
4. **Configuration Validation Page** - Manage external system validations (optional, can be part of Admin)

The most critical addition is the **Validators tab in the Admin page**, which provides the core functionality for managing the validator registry system.

