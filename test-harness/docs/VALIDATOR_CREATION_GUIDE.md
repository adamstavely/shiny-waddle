# Validator Creation Guide

This guide shows you how to create custom validators for Sentinel using the new extensibility architecture.

## Quick Start

Creating a validator is now just 3 steps:

1. **Extend `BaseValidator`**
2. **Implement `runTestsInternal()`**
3. **Register with the registry**

## Example: Creating a Simple Validator

```typescript
import { BaseValidator } from '../core/base-validator';
import { ValidatorMetadata } from '../core/validator-registry';
import { TestResult, TestSuite } from '../core/types';

export class MyValidator extends BaseValidator {
  readonly id = 'my-validator';
  readonly name = 'My Custom Validator';
  readonly description = 'Validates something important';
  readonly testType = 'custom-validation';
  readonly version = '1.0.0';

  readonly metadata: ValidatorMetadata = {
    requiredConfig: ['apiKey'],
    tags: ['custom', 'api'],
  };

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Your validation logic here
    const isValid = await this.checkSomething();

    results.push(
      this.createTestResult(
        'My validation check',
        isValid,
        { details: '...' }
      )
    );

    return results;
  }

  private async checkSomething(): Promise<boolean> {
    // Your validation logic
    return true;
  }
}
```

## Registering Your Validator

```typescript
import { validatorRegistry } from '../core/validator-registry';
import { MyValidator } from './my-validator';

// Create and register
const validator = new MyValidator({
  apiKey: process.env.API_KEY,
});

validatorRegistry.register(validator);
```

## Base Validator Features

The `BaseValidator` class provides:

### Helper Methods

- `createTestResult()` - Create a test result
- `createPassedResult()` - Create a passed test result
- `createFailedResult()` - Create a failed test result

### Automatic Features

- **Error Handling**: Errors are caught and returned as failed test results
- **Configuration Validation**: Override `validateConfig()` to validate config
- **Suite Filtering**: Override `shouldRun()` to control when validator runs

## Configuration Validation

Override `validateConfig()` to validate your validator's configuration:

```typescript
validateConfig(config: any): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!config.apiKey) {
    errors.push('apiKey is required');
  }

  if (!config.endpoint) {
    errors.push('endpoint is required');
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}
```

## Custom Suite Filtering

Override `shouldRun()` to control when your validator executes:

```typescript
protected shouldRun(suite: TestSuite): boolean {
  // Only run if suite has specific flag
  return (suite as any).includeMyCustomTests === true;
}
```

## Complete Example: Salesforce Validator

```typescript
import { BaseValidator } from '../core/base-validator';
import { TestResult, TestSuite } from '../core/types';

interface SalesforceConfig {
  username: string;
  password: string;
  securityToken?: string;
}

export class SalesforceValidator extends BaseValidator {
  readonly id = 'salesforce';
  readonly name = 'Salesforce Configuration Validator';
  readonly description = 'Validates Salesforce org configuration';
  readonly testType = 'configuration-validation';
  readonly version = '1.0.0';

  private config: SalesforceConfig;

  constructor(config: SalesforceConfig) {
    super(config);
    this.config = config;
  }

  protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
    const results: TestResult[] = [];

    // Connect to Salesforce
    const client = await this.connectToSalesforce();

    // Get rules from suite
    const rules = (suite as any).salesforceRules || [];

    for (const rule of rules) {
      const result = await this.validateRule(client, rule);
      results.push(
        this.createTestResult(
          `Salesforce: ${rule.name}`,
          result.passed,
          result
        )
      );
    }

    return results;
  }

  private async connectToSalesforce(): Promise<any> {
    // Use jsforce or similar
    // const jsforce = require('jsforce');
    // const conn = new jsforce.Connection({ ... });
    // await conn.login(this.config.username, this.config.password);
    // return conn;
    throw new Error('Not implemented');
  }

  private async validateRule(client: any, rule: any): Promise<any> {
    // Implement rule validation
    return { passed: true, message: 'OK' };
  }

  validateConfig(config: any): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.username) errors.push('username required');
    if (!config.password) errors.push('password required');

    return { valid: errors.length === 0, errors };
  }
}
```

## Best Practices

### 1. Use Descriptive IDs

```typescript
readonly id = 'salesforce-config'; // Good
readonly id = 'sf'; // Bad - too short
```

### 2. Provide Metadata

```typescript
readonly metadata: ValidatorMetadata = {
  requiredConfig: ['apiKey', 'endpoint'],
  optionalConfig: ['timeout'],
  tags: ['api', 'external'],
  exampleConfig: {
    apiKey: 'your-api-key',
    endpoint: 'https://api.example.com',
  },
};
```

### 3. Handle Errors Gracefully

The base class catches errors, but you can also handle them explicitly:

```typescript
protected async runTestsInternal(suite: TestSuite): Promise<TestResult[]> {
  try {
    // Your logic
  } catch (error: any) {
    return [
      this.createFailedResult(
        'Connection failed',
        error.message,
        { error: error.stack }
      ),
    ];
  }
}
```

### 4. Return Meaningful Details

```typescript
results.push(
  this.createTestResult(
    'MFA Check',
    allProfilesHaveMFA,
    {
      totalProfiles: 10,
      profilesWithoutMFA: 2,
      profiles: ['Profile1', 'Profile2'],
    }
  )
);
```

### 5. Use Helper Methods

```typescript
// Good - uses helper
this.createPassedResult('Test passed', { details: '...' });

// Also good - but more verbose
this.createTestResult('Test passed', true, { details: '...' });
```

## Testing Your Validator

```typescript
import { SalesforceValidator } from './salesforce-validator';

describe('SalesforceValidator', () => {
  it('should validate configuration', () => {
    const validator = new SalesforceValidator({
      username: 'test@example.com',
      password: 'password',
    });

    expect(validator.id).toBe('salesforce');
    expect(validator.name).toBe('Salesforce Configuration Validator');
  });

  it('should reject invalid config', () => {
    expect(() => {
      new SalesforceValidator({} as any);
    }).toThrow();
  });
});
```

## Integration with Sentinel

Once registered, validators are automatically discovered and used:

```typescript
import { Sentinel } from '../core/test-harness';
import { validatorRegistry } from '../core/validator-registry';
import { SalesforceValidator } from './salesforce-validator';

// Register validators
validatorRegistry.register(
  new SalesforceValidator({ username: '...', password: '...' })
);

// Sentinel automatically uses registered validators
const sentinel = new Sentinel(config);
const results = await sentinel.runTestSuite(suite);
```

## Next Steps

- See `validators/example-salesforce-validator.ts` for a complete example
- Check `core/base-validator.ts` for all available methods
- Review `core/validator-registry.ts` for registry API

