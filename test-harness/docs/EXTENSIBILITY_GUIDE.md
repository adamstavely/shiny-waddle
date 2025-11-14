# TestOrchestrator Extensibility Guide

## Overview

TestOrchestrator is designed to be extensible for different types of compliance and configuration validation. While the current implementation focuses on access control testing (RBAC/ABAC), data behavior validation, and contract testing, the architecture supports adding new test types and custom validators.

## Current Architecture

### Test Types

The framework currently supports four main test types:

1. **Access Control Tests** (`access-control`)
   - Validates RBAC/ABAC policies
   - Tests user permissions against resources
   - Uses Policy Decision Point (PDP) for evaluation

2. **Data Behavior Tests** (`data-behavior`)
   - Validates query patterns
   - Checks field access, filters, and joins
   - Detects PII exposure

3. **Contract Tests** (`contract`)
   - Validates data contracts
   - Tests field restrictions and aggregation requirements

4. **Dataset Health Tests** (`dataset-health`)
   - Validates privacy thresholds
   - Tests statistical fidelity of masked/synthetic data

### Policy System

Policies are JSON-based and support:
- **RBAC Policies**: Role-based access control rules
- **ABAC Policies**: Attribute-based access control with conditions
- **Policy Engines**: Custom, OPA (Open Policy Agent), Cedar

### Extensibility Points

1. **Test Types**: Add new test types by extending `TestResult` and `TestSuite`
2. **Testers**: Create custom tester classes (like `AccessControlTester`)
3. **Policies**: Define custom policy structures and validators
4. **Scanners**: Implement custom scanners for configuration validation

## Adding Configuration Validation (Salesforce/Elastic Cloud)

To add validation for external systems like Salesforce or Elastic Cloud, you would need to:

### 1. Create a New Test Type

Extend the `TestResult` type to include configuration validation:

```typescript
// In core/types.ts
export interface TestResult {
  testType: 'access-control' | 'data-behavior' | 'contract' | 'dataset-health' | 'configuration-validation';
  testName: string;
  passed: boolean;
  details: any;
  timestamp: Date;
  error?: string;
}

// Add configuration validation types
export interface ConfigurationValidationTest {
  name: string;
  target: 'salesforce' | 'elastic-cloud' | 'aws' | 'custom';
  rules: ConfigurationRule[];
  connectionConfig: ConnectionConfig;
}

export interface ConfigurationRule {
  id: string;
  name: string;
  description: string;
  check: string; // e.g., "allProfilesHaveMFA" or "indicesHaveRetentionPolicy"
  expectedValue: any;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface ConnectionConfig {
  type: 'salesforce' | 'elastic-cloud' | 'api';
  credentials: {
    endpoint?: string;
    apiKey?: string;
    username?: string;
    password?: string;
    accessToken?: string;
    [key: string]: any;
  };
}
```

### 2. Create a Configuration Validator Service

```typescript
// services/configuration-validator.ts
import { ConfigurationValidationTest, ConfigurationRule, ConnectionConfig } from '../core/types';

export class ConfigurationValidator {
  private validators: Map<string, (config: ConnectionConfig, rule: ConfigurationRule) => Promise<ValidationResult>>;

  constructor() {
    this.validators = new Map();
    this.registerValidators();
  }

  private registerValidators() {
    // Register Salesforce validator
    this.validators.set('salesforce', this.validateSalesforce.bind(this));
    
    // Register Elastic Cloud validator
    this.validators.set('elastic-cloud', this.validateElasticCloud.bind(this));
  }

  async validate(test: ConfigurationValidationTest): Promise<ValidationResult[]> {
    const validator = this.validators.get(test.target);
    if (!validator) {
      throw new Error(`No validator registered for target: ${test.target}`);
    }

    const results: ValidationResult[] = [];
    for (const rule of test.rules) {
      const result = await validator(test.connectionConfig, rule);
      results.push(result);
    }

    return results;
  }

  private async validateSalesforce(
    config: ConnectionConfig,
    rule: ConfigurationRule
  ): Promise<ValidationResult> {
    // Connect to Salesforce API
    const salesforceClient = await this.connectToSalesforce(config);
    
    switch (rule.check) {
      case 'allProfilesHaveMFA':
        return await this.checkSalesforceMFA(salesforceClient, rule);
      
      case 'noPublicSharing':
        return await this.checkPublicSharing(salesforceClient, rule);
      
      case 'passwordPolicyCompliant':
        return await this.checkPasswordPolicy(salesforceClient, rule);
      
      default:
        return {
          ruleId: rule.id,
          passed: false,
          message: `Unknown Salesforce check: ${rule.check}`,
        };
    }
  }

  private async validateElasticCloud(
    config: ConnectionConfig,
    rule: ConfigurationRule
  ): Promise<ValidationResult> {
    // Connect to Elastic Cloud API
    const elasticClient = await this.connectToElasticCloud(config);
    
    switch (rule.check) {
      case 'indicesHaveRetentionPolicy':
        return await this.checkIndexRetention(elasticClient, rule);
      
      case 'allIndicesEncrypted':
        return await this.checkIndexEncryption(elasticClient, rule);
      
      case 'clusterSecurityEnabled':
        return await this.checkClusterSecurity(elasticClient, rule);
      
      default:
        return {
          ruleId: rule.id,
          passed: false,
          message: `Unknown Elastic Cloud check: ${rule.check}`,
        };
    }
  }

  // Salesforce-specific validators
  private async checkSalesforceMFA(client: any, rule: ConfigurationRule): Promise<ValidationResult> {
    // Query Salesforce API for all profiles
    const profiles = await client.query('SELECT Id, Name, PermissionsMultiFactorAuth FROM Profile');
    
    const nonMFAProfiles = profiles.records.filter(
      (p: any) => !p.PermissionsMultiFactorAuth
    );
    
    return {
      ruleId: rule.id,
      passed: nonMFAProfiles.length === 0,
      message: nonMFAProfiles.length === 0
        ? 'All profiles have MFA enabled'
        : `Found ${nonMFAProfiles.length} profiles without MFA: ${nonMFAProfiles.map((p: any) => p.Name).join(', ')}`,
      details: {
        totalProfiles: profiles.records.length,
        nonMFAProfiles: nonMFAProfiles.length,
        profiles: nonMFAProfiles,
      },
    };
  }

  // Elastic Cloud-specific validators
  private async checkIndexRetention(client: any, rule: ConfigurationRule): Promise<ValidationResult> {
    // Query Elastic Cloud API for indices
    const indices = await client.indices.get({ index: '*' });
    
    const indicesWithoutRetention = [];
    for (const [indexName, indexData] of Object.entries(indices)) {
      const settings = (indexData as any).settings;
      if (!settings || !settings['index.lifecycle.name']) {
        indicesWithoutRetention.push(indexName);
      }
    }
    
    return {
      ruleId: rule.id,
      passed: indicesWithoutRetention.length === 0,
      message: indicesWithoutRetention.length === 0
        ? 'All indices have retention policies'
        : `Found ${indicesWithoutRetention.length} indices without retention policies`,
      details: {
        totalIndices: Object.keys(indices).length,
        indicesWithoutRetention: indicesWithoutRetention.length,
        indices: indicesWithoutRetention,
      },
    };
  }

  // Connection helpers
  private async connectToSalesforce(config: ConnectionConfig): Promise<any> {
    // Use jsforce or similar library
    // const jsforce = require('jsforce');
    // const conn = new jsforce.Connection({ ... });
    // await conn.login(config.credentials.username, config.credentials.password);
    // return conn;
    throw new Error('Salesforce connection not implemented');
  }

  private async connectToElasticCloud(config: ConnectionConfig): Promise<any> {
    // Use @elastic/elasticsearch client
    // const { Client } = require('@elastic/elasticsearch');
    // const client = new Client({
    //   cloud: { id: config.credentials.cloudId },
    //   auth: { apiKey: config.credentials.apiKey },
    // });
    // return client;
    throw new Error('Elastic Cloud connection not implemented');
  }
}

export interface ValidationResult {
  ruleId: string;
  passed: boolean;
  message: string;
  details?: any;
}
```

### 3. Extend the TestOrchestrator Class

```typescript
// In core/test-harness.ts
import { ConfigurationValidator } from '../services/configuration-validator';

export class TestOrchestrator {
  // ... existing properties
  private configurationValidator?: ConfigurationValidator;

  constructor(config: TestConfiguration) {
    // ... existing initialization
    
    // Initialize configuration validator if needed
    if (config.configurationValidationConfig) {
      this.configurationValidator = new ConfigurationValidator();
    }
  }

  async runConfigurationValidationTests(
    suite: TestSuite
  ): Promise<TestResult[]> {
    if (!this.configurationValidator || !suite.configurationTests) {
      return [];
    }

    const results: TestResult[] = [];

    for (const test of suite.configurationTests) {
      const validationResults = await this.configurationValidator.validate(test);

      for (const result of validationResults) {
        results.push({
          testType: 'configuration-validation',
          testName: `${test.name}: ${result.ruleId}`,
          passed: result.passed,
          details: result,
          timestamp: new Date(),
        });
      }
    }

    return results;
  }
}
```

### 4. Define Policy/Test Structure

Create a policy file for Salesforce validation:

```json
{
  "name": "Salesforce Org Compliance Policy",
  "version": "1.0.0",
  "target": "salesforce",
  "rules": [
    {
      "id": "sf-mfa-required",
      "name": "MFA Required for All Profiles",
      "description": "All user profiles must have Multi-Factor Authentication enabled",
      "check": "allProfilesHaveMFA",
      "expectedValue": true,
      "severity": "critical"
    },
    {
      "id": "sf-no-public-sharing",
      "name": "No Public Sharing",
      "description": "No objects should have public sharing enabled",
      "check": "noPublicSharing",
      "expectedValue": true,
      "severity": "high"
    },
    {
      "id": "sf-password-policy",
      "name": "Password Policy Compliance",
      "description": "Password policy must meet minimum requirements",
      "check": "passwordPolicyCompliant",
      "expectedValue": {
        "minLength": 12,
        "requireMixedCase": true,
        "requireNumbers": true,
        "requireSpecialChars": true
      },
      "severity": "high"
    }
  ],
  "connectionConfig": {
    "type": "salesforce",
    "credentials": {
      "username": "${SALESFORCE_USERNAME}",
      "password": "${SALESFORCE_PASSWORD}",
      "securityToken": "${SALESFORCE_SECURITY_TOKEN}"
    }
  }
}
```

Create a policy file for Elastic Cloud validation:

```json
{
  "name": "Elastic Cloud Tenant Compliance Policy",
  "version": "1.0.0",
  "target": "elastic-cloud",
  "rules": [
    {
      "id": "ec-retention-policy",
      "name": "All Indices Must Have Retention Policy",
      "description": "All indices must have an Index Lifecycle Management (ILM) policy configured",
      "check": "indicesHaveRetentionPolicy",
      "expectedValue": true,
      "severity": "high"
    },
    {
      "id": "ec-encryption-required",
      "name": "All Indices Must Be Encrypted",
      "description": "All indices must have encryption at rest enabled",
      "check": "allIndicesEncrypted",
      "expectedValue": true,
      "severity": "critical"
    },
    {
      "id": "ec-cluster-security",
      "name": "Cluster Security Enabled",
      "description": "Elasticsearch security features must be enabled",
      "check": "clusterSecurityEnabled",
      "expectedValue": true,
      "severity": "critical"
    }
  ],
  "connectionConfig": {
    "type": "elastic-cloud",
    "credentials": {
      "cloudId": "${ELASTIC_CLOUD_ID}",
      "apiKey": "${ELASTIC_API_KEY}"
    }
  }
}
```

## Implementation Steps

### Step 1: Add Dependencies

```bash
npm install jsforce @elastic/elasticsearch
npm install --save-dev @types/jsforce
```

### Step 2: Create the Validator Service

Create `services/configuration-validator.ts` with the implementation above.

### 3. Extend Types

Add configuration validation types to `core/types.ts`.

### Step 4: Update Test Suite Loader

Extend the test suite loader to support configuration tests.

### Step 5: Create Policy Files

Create policy JSON files for Salesforce and Elastic Cloud.

### Step 6: Integrate with Dashboard

Update the dashboard to display configuration validation results.

## Plugin Architecture (Future Enhancement)

For even better extensibility, consider a plugin architecture:

```typescript
// plugins/salesforce-validator.ts
export class SalesforceValidatorPlugin implements ValidatorPlugin {
  name = 'salesforce';
  
  async validate(config: ConnectionConfig, rules: ConfigurationRule[]): Promise<ValidationResult[]> {
    // Implementation
  }
  
  getSupportedChecks(): string[] {
    return ['allProfilesHaveMFA', 'noPublicSharing', 'passwordPolicyCompliant'];
  }
}

// Register plugin
TestOrchestrator.registerValidatorPlugin(new SalesforceValidatorPlugin());
```

## Improved Extensibility Architecture

To make it **much easier** to add validators, TestOrchestrator now includes:

### 1. Validator Registry System

A centralized registry for managing validators:

```typescript
import { validatorRegistry } from '../core/validator-registry';
import { SalesforceValidator } from '../validators/example-salesforce-validator';

// Register a validator
const salesforceValidator = new SalesforceValidator({
  connection: { username: '...', password: '...' },
  rules: [...],
});

validatorRegistry.register(salesforceValidator);
```

### 2. Base Validator Class

An abstract base class that provides common functionality:

```typescript
import { BaseValidator } from '../core/base-validator';
import { TestResult, TestSuite } from '../core/types';

export class MyCustomValidator extends BaseValidator {
  readonly id = 'my-validator';
  readonly name = 'My Custom Validator';
  readonly description = 'Validates something custom';
  readonly testType = 'custom-validation';
  readonly version = '1.0.0';

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    // Your validation logic here
    return [
      this.createPassedResult('Test 1', { details: '...' }),
      this.createFailedResult('Test 2', 'Reason for failure'),
    ];
  }
}
```

### 3. Benefits of the New Architecture

✅ **No Core Changes Needed**: Add validators without modifying `TestOrchestrator` class
✅ **Standard Interface**: All validators implement the same interface
✅ **Automatic Discovery**: Registry can find validators for test suites
✅ **Configuration Validation**: Built-in config validation
✅ **Error Handling**: Base class handles errors gracefully
✅ **Metadata Support**: Validators can describe themselves

### 4. Example: Adding a Salesforce Validator (3 Steps)

**Step 1: Create the Validator**

```typescript
// validators/salesforce-validator.ts
import { BaseValidator } from '../core/base-validator';

export class SalesforceValidator extends BaseValidator {
  readonly id = 'salesforce';
  readonly name = 'Salesforce Validator';
  readonly testType = 'configuration-validation';
  // ... implement runTestsInternal()
}
```

**Step 2: Register It**

```typescript
// In your initialization code
import { validatorRegistry } from '../core/validator-registry';
import { SalesforceValidator } from '../validators/salesforce-validator';

const validator = new SalesforceValidator(config);
validatorRegistry.register(validator);
```

**Step 3: Use It**

The `TestOrchestrator` class automatically discovers and uses registered validators:

```typescript
const orchestrator = new TestOrchestrator(config);
// Validators are automatically discovered and used
const results = await orchestrator.runTestSuite(suite);
```

### 5. Dynamic Validator Loading

Validators can be loaded from configuration:

```typescript
// config/validators.json
{
  "validators": [
    {
      "type": "salesforce",
      "enabled": true,
      "config": { ... }
    },
    {
      "type": "elastic-cloud",
      "enabled": true,
      "config": { ... }
    }
  ]
}
```

### 6. Validator Discovery

Query the registry to see what's available:

```typescript
// List all validators
const validators = validatorRegistry.list();
console.log(validators);
// [
//   { id: 'access-control', name: 'Access Control Validator', ... },
//   { id: 'salesforce', name: 'Salesforce Validator', ... },
// ]

// Find validators for a test suite
const applicableValidators = validatorRegistry.findValidatorsForSuite(suite);

// Get validators by type
const configValidators = validatorRegistry.getByType('configuration-validation');
```

## Summary

The TestOrchestrator framework is now **highly extensible** for adding validators:

✅ **What's Easy:**
- Creating new validators (extend `BaseValidator`)
- Registering validators (one line: `registry.register()`)
- No core code changes needed
- Standard interface and error handling
- Automatic discovery and execution

✅ **What's Still Required:**
- Implementing validation logic (system-specific)
- Creating API clients for external systems
- Defining policy/rule structures

🔧 **Recommended Approach:**
1. Extend `BaseValidator` class
2. Implement `runTestsInternal()` method
3. Register validator with `validatorRegistry.register()`
4. That's it! The framework handles the rest.

The new architecture makes adding validators as simple as creating a class and registering it - no need to modify core framework code.

