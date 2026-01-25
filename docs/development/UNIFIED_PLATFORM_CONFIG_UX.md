# Unified Platform Configuration UX

## Problem Statement

Previously, we had two separate concepts that were confusing for users:
1. **Platform Baselines** - Desired state configurations
2. **Configuration Validation Targets** - Separate system for validating external systems

Users didn't understand:
- When to use baselines vs validation targets
- How baselines relate to validation targets
- Why they needed to create separate entities for the same platform

## Solution: Clear Separation (Like Applications)

### Core Concept

**Platform Instance (like Application) = The target being validated**
**Platform Baseline = The standard to compare against**

Just like:
- **Application** = The thing being tested
- **Policy** = The standard to test against
- **Test** = Compare application against policy

For Platform Configurations:
- **Platform Instance** = The live system being validated (e.g., "Production Salesforce Org")
- **Platform Baseline** = The desired state standard (e.g., "Salesforce HIPAA Baseline")
- **Validation** = Compare instance against baseline

Instead of:
- ❌ Create Baseline → Create Validation Target → Create Rules → Run Validation

Users now:
- ✅ Create Platform Baseline (the standard)
- ✅ Create Platform Instance (the target, like an Application)
- ✅ Validate Instance against Baseline (one button)

### Clear Structure

**Platform Baseline** (the standard):
```typescript
PlatformBaseline {
  id: string
  name: "Salesforce HIPAA Baseline"
  platform: "salesforce"
  environment: "production" // Which environment this baseline applies to
  version: "1.0"
  
  // Desired state configuration
  config: {
    encryption: { enabled: true },
    fieldLevelSecurity: { ... },
    sharingRules: { ... }
  }
  
  // Validation rules (auto-generated from config + custom)
  validationRules: [
    { check: "encryption.enabled === true", severity: "critical" },
    { check: "allProfilesHaveMFA", severity: "high" }
  ]
}
```

**Platform Instance** (the target, like Application):
```typescript
PlatformInstance {
  id: string
  name: "Production Salesforce Org"
  platform: "salesforce"
  environment: "production"
  
  // Connection to live system
  connection: {
    endpoint: "https://myorg.salesforce.com"
    credentials: { ... } // Encrypted
  }
  
  // Which baseline to validate against
  baselineId: "baseline-123"
  
  // Status from last validation
  status: "healthy" | "warnings" | "errors"
  lastValidatedAt: Date
}
```

### User Workflow

#### 1. Create Platform Baseline (the standard)

**Define the desired state:**

```
┌─────────────────────────────────────────┐
│ Platform Baseline                         │
├─────────────────────────────────────────┤
│ Basic Info                              │
│ - Name: Salesforce HIPAA Baseline        │
│ - Platform: Salesforce                  │
│ - Environment: Production                │
│                                         │
│ Baseline Configuration                  │
│ [Platform-specific config form]        │
│ - Encryption: Enabled                    │
│ - Field-Level Security: ...              │
│ - Sharing Rules: ...                     │
│                                         │
│ Validation Rules                        │
│ ✓ Auto-generate from baseline           │
│ + Add custom rule                       │
└─────────────────────────────────────────┘
```

#### 2. Create Platform Instance (the target)

**Define the live system to validate:**

```
┌─────────────────────────────────────────┐
│ Platform Instance                         │
├─────────────────────────────────────────┤
│ Basic Info                              │
│ - Name: Production Salesforce Org        │
│ - Platform: Salesforce                  │
│ - Environment: Production                │
│                                         │
│ Connection                              │
│ - Endpoint: https://myorg.salesforce.com │
│ - Credentials: [Connect]                 │
│                                         │
│ Baseline                                │
│ - Select Baseline: [Salesforce HIPAA...] │
└─────────────────────────────────────────┘
```

#### 3. Validate Instance against Baseline

**One button compares target to standard:**

```
┌─────────────────────────────────────────┐
│ Production Salesforce Org               │
│ Platform: Salesforce | Env: Production  │
│ Baseline: Salesforce HIPAA Baseline      │
├─────────────────────────────────────────┤
│ Status: ⚠️ Warnings                     │
│ Last Validated: 2 hours ago             │
│                                         │
│ [🔍 Validate Against Baseline]          │
│                                         │
│ When clicked:                           │
│ 1. Connects to live system              │
│ 2. Fetches current config               │
│ 3. Compares to baseline                 │
│ 4. Runs validation rules                │
│ 5. Shows comparison results             │
└─────────────────────────────────────────┘
```

#### 3. View Results

**Unified results view:**

```
┌─────────────────────────────────────────┐
│ Validation Results                      │
├─────────────────────────────────────────┤
│ Overall Status: ⚠️ 2 Warnings           │
│                                         │
│ Baseline Comparison                    │
│ ✓ Encryption: Enabled (matches)         │
│ ⚠️ FLS: Missing 3 field rules           │
│                                         │
│ Validation Rules                       │
│ ✓ MFA enabled for all profiles         │
│ ⚠️ Public sharing detected              │
└─────────────────────────────────────────┘
```

### Key Benefits

1. **Clear Separation of Concerns**
   - **Baseline** = The standard (like a Policy)
   - **Instance** = The target (like an Application)
   - Clear mental model: "Does this instance match the baseline?"

2. **Reusable Baselines**
   - One baseline can be used by multiple instances
   - Example: "Salesforce HIPAA Baseline" used by Prod, Staging, Dev instances
   - Similar to how one Policy can be tested by multiple Applications

3. **Auto-Generated Rules**
   - Validation rules automatically created from baseline config
   - Users can add custom rules to baseline if needed
   - Rules travel with the baseline

4. **Familiar Pattern**
   - Same pattern as Applications → Policies → Tests
   - Users already understand this model
   - Consistent UX across the platform

5. **Clear Workflow**
   - Step 1: Define the standard (Baseline)
   - Step 2: Define what to validate (Instance)
   - Step 3: Validate instance against baseline

### Migration Path

**For existing users:**

1. **Baselines** → Stay as Platform Baselines (the standard)
2. **Validation Targets** → Become Platform Instances (the targets)
3. **Validation Rules** → Move to Baselines (auto-generated + custom)

**Backward Compatibility:**
- Existing baselines stay as baselines
- Validation targets become instances that reference baselines
- Rules move to baselines (one baseline can have many rules)

### Implementation Notes

1. **Baseline = The Standard**
   - Contains desired state configuration
   - Contains validation rules (auto-generated + custom)
   - Can be reused by multiple instances
   - Environment-specific (e.g., "Production Salesforce Baseline")

2. **Instance = The Target**
   - Contains connection info to live system
   - References a baseline to validate against
   - Like an Application - it's the thing being validated
   - One instance validates against one baseline

3. **Validation = Comparison**
   - Connects to live system via instance connection
   - Fetches current configuration
   - Compares to baseline configuration
   - Runs baseline validation rules
   - Shows comparison results

4. **Multiple Instances, One Baseline**
   - Example: "Salesforce HIPAA Baseline" used by:
     - "Production Salesforce Org" instance
     - "Staging Salesforce Org" instance
     - "Dev Salesforce Org" instance

### Example: Salesforce Baseline + Instance

**Baseline (the standard):**
```typescript
{
  id: "baseline-123",
  name: "Salesforce HIPAA Baseline",
  platform: "salesforce",
  environment: "production",
  version: "1.0",
  
  config: {
    encryption: {
      fieldEncryption: { enabled: true },
      platformEncryption: { enabled: true }
    },
    fieldLevelSecurity: {
      profiles: { /* FLS rules */ }
    },
    sharingModel: {
      defaultAccess: "Private"
    }
  },
  
  // Auto-generated from config + custom:
  validationRules: [
    { check: "encryption.fieldEncryption.enabled === true", severity: "critical", autoGenerated: true },
    { check: "sharingModel.defaultAccess === 'Private'", severity: "high", autoGenerated: true },
    { check: "allProfilesHaveMFA", severity: "high", autoGenerated: false } // Custom
  ]
}
```

**Instance (the target):**
```typescript
{
  id: "instance-456",
  name: "Production Salesforce Org",
  platform: "salesforce",
  environment: "production",
  
  connection: {
    endpoint: "https://myorg.salesforce.com",
    credentials: { /* encrypted */ }
  },
  
  baselineId: "baseline-123", // References the baseline above
  status: "warnings",
  lastValidatedAt: "2026-01-24T10:00:00Z"
}
```

**Validation Flow:**
When user clicks "Validate" on the instance:
1. Loads baseline (baseline-123)
2. Connects to Salesforce API via instance connection
3. Fetches current config from live system
4. Compares current config to baseline config
5. Runs baseline validation rules
6. Shows comparison results

## Summary

**Before:** 3 separate concepts (Baselines, Validation Targets, Rules) → Confusing
**After:** 2 clear concepts (Baseline = standard, Instance = target) → Clear

The unified approach makes it obvious:
- **Baseline** = The standard (like a Policy)
- **Instance** = The target being validated (like an Application)
- **Validation** = Compare instance against baseline

**Same pattern as Applications:**
- Application → Policy → Test
- Platform Instance → Platform Baseline → Validation

This is a familiar pattern users already understand!
