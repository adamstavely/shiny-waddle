# Service Implementation Guide

This guide provides detailed information about implementing and extending services in the Heimdall Dashboard API.

## Table of Contents

1. [Service Architecture](#service-architecture)
2. [Service Structure](#service-structure)
3. [Provider Interfaces](#provider-interfaces)
4. [Configuration](#configuration)
5. [Error Handling](#error-handling)
6. [Adding New Services](#adding-new-services)
7. [Best Practices](#best-practices)

## Service Architecture

Services in Heimdall follow a layered architecture:

```
Controller (HTTP Layer)
    ↓
Service (Business Logic)
    ↓
Tester/Provider (Core Logic)
    ↓
External Systems (Optional)
```

### Layer Responsibilities

- **Controller**: Handles HTTP requests, validation, logging
- **Service**: Business logic, error handling, validation
- **Tester/Provider**: Core testing logic, can integrate with real systems
- **External Systems**: Real databases, APIs, etc. (via providers)

## Service Structure

### Basic Service Structure

```typescript
import { Injectable, Logger } from '@nestjs/common';
import { SomeTester } from '../../../services/some-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class SomeService {
  private readonly logger = new Logger(SomeService.name);
  private tester: SomeTester;

  constructor() {
    this.tester = new SomeTester();
  }

  async someMethod(dto: SomeDto) {
    try {
      // Validate input
      this.validateInput(dto);

      // Call tester
      const result = await this.tester.someMethod(dto);

      return result;
    } catch (error: any) {
      this.logger.error(`Error in someMethod: ${error.message}`, error.stack);
      
      if (error instanceof ValidationException) {
        throw error;
      }
      
      throw new InternalServerException(
        'Failed to execute someMethod',
        { originalError: error.message },
      );
    }
  }

  private validateInput(dto: SomeDto) {
    if (!dto.requiredField) {
      throw new ValidationException('requiredField is required');
    }
  }
}
```

## Provider Interfaces

Services can be enhanced with provider interfaces for real system integration.

### Example: Database Metadata Provider

```typescript
// In service file
export interface DatabaseMetadataProvider {
  getTables(database: DatabaseConfig): Promise<string[]>;
  getRLSPolicies(database: DatabaseConfig): Promise<RLSPolicy[]>;
  getCLSPolicies(database: DatabaseConfig): Promise<CLSPolicy[]>;
}

export interface RLSCLSTesterConfig {
  metadataProvider?: DatabaseMetadataProvider;
  mockData?: {
    tables?: string[];
    rlsPolicies?: RLSPolicy[];
  };
}

export class RLSCLSTester {
  private metadataProvider?: DatabaseMetadataProvider;
  private config: RLSCLSTesterConfig;

  constructor(config?: RLSCLSTesterConfig) {
    this.config = config || {};
    this.metadataProvider = this.config.metadataProvider;
  }

  private async getDatabaseTables(database: DatabaseConfig): Promise<string[]> {
    // Use real provider if available
    if (this.metadataProvider) {
      try {
        return await this.metadataProvider.getTables(database);
      } catch (error: any) {
        throw new Error(`Failed to get database tables: ${error.message}`);
      }
    }
    
    // Fallback to mock data
    return this.config.mockData?.tables || ['users', 'orders'];
  }
}
```

### Implementing a Provider

To integrate with a real system, implement the provider interface:

```typescript
class PostgreSQLMetadataProvider implements DatabaseMetadataProvider {
  async getTables(database: DatabaseConfig): Promise<string[]> {
    // Connect to PostgreSQL and query information_schema
    const client = new Client(database);
    const result = await client.query(
      "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'"
    );
    return result.rows.map(row => row.table_name);
  }

  async getRLSPolicies(database: DatabaseConfig): Promise<RLSPolicy[]> {
    // Query pg_policies view
    // ...
  }

  async getCLSPolicies(database: DatabaseConfig): Promise<CLSPolicy[]> {
    // Query column-level policies
    // ...
  }
}

// Use in service
const tester = new RLSCLSTester({
  metadataProvider: new PostgreSQLMetadataProvider(),
});
```

## Configuration

Services support configuration for flexibility and testing.

### Configuration Pattern

```typescript
export interface ServiceConfig {
  // Optional provider for real integrations
  provider?: SomeProvider;
  
  // Optional mock data for testing
  mockData?: {
    // Mock data structure
  };
  
  // Optional configuration options
  options?: {
    // Configurable behavior
  };
}

export class SomeTester {
  private config: ServiceConfig;

  constructor(config?: ServiceConfig) {
    this.config = config || {};
  }

  async someMethod() {
    // Use provider if available
    if (this.config.provider) {
      return await this.config.provider.someMethod();
    }
    
    // Fallback to mock data
    return this.config.mockData?.someData || defaultData;
  }
}
```

### Backward Compatibility

Services maintain backward compatibility with old constructor signatures:

```typescript
// Old way (still works)
const tester = new SomeTester();

// New way (with config)
const tester = new SomeTester({
  provider: new RealProvider(),
  mockData: { /* ... */ },
});
```

## Error Handling

All services follow a consistent error handling pattern.

### Error Types

```typescript
// Validation errors
throw new ValidationException('Field is required');

// Not found errors
throw new NotFoundException('Resource not found');

// Authorization errors
throw new UnauthorizedException('Not authorized');
throw new ForbiddenException('Access forbidden');

// Internal errors
throw new InternalServerException(
  'Operation failed',
  { originalError: error.message },
);
```

### Error Handling Pattern

```typescript
async someMethod(dto: SomeDto) {
  try {
    // Validate input
    this.validateInput(dto);

    // Execute operation
    const result = await this.tester.someMethod(dto);

    return result;
  } catch (error: any) {
    this.logger.error(`Error in someMethod: ${error.message}`, error.stack);
    
    // Re-throw known exceptions
    if (error instanceof ValidationException ||
        error instanceof NotFoundException ||
        error instanceof UnauthorizedException ||
        error instanceof ForbiddenException) {
      throw error;
    }
    
    // Wrap unknown errors
    throw new InternalServerException(
      'Failed to execute someMethod',
      { originalError: error.message },
    );
  }
}
```

## Adding New Services

### Step 1: Create Service File

Create a service file in `services/`:

```typescript
// services/new-feature-tester.ts
export interface NewFeatureProvider {
  // Define provider interface
}

export interface NewFeatureTesterConfig {
  provider?: NewFeatureProvider;
  mockData?: { /* ... */ };
}

export class NewFeatureTester {
  private config: NewFeatureTesterConfig;

  constructor(config?: NewFeatureTesterConfig) {
    this.config = config || {};
  }

  async testFeature(input: any): Promise<TestResult> {
    // Implementation
  }
}
```

### Step 2: Create NestJS Service

Create a NestJS service in `dashboard-api/src/new-feature/`:

```typescript
// dashboard-api/src/new-feature/new-feature.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { NewFeatureTester } from '../../../services/new-feature-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

@Injectable()
export class NewFeatureService {
  private readonly logger = new Logger(NewFeatureService.name);
  private tester: NewFeatureTester;

  constructor() {
    this.tester = new NewFeatureTester();
  }

  async testFeature(dto: { input: any }) {
    try {
      this.validateInput(dto);
      return await this.tester.testFeature(dto.input);
    } catch (error: any) {
      this.logger.error(`Error: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException('Failed to test feature', {
        originalError: error.message,
      });
    }
  }

  private validateInput(dto: { input: any }) {
    if (!dto.input) {
      throw new ValidationException('input is required');
    }
  }
}
```

### Step 3: Create Controller

```typescript
// dashboard-api/src/new-feature/new-feature.controller.ts
import { Controller, Post, Body, HttpCode, HttpStatus, ValidationPipe, Logger } from '@nestjs/common';
import { NewFeatureService } from './new-feature.service';

@Controller('api/new-feature')
export class NewFeatureController {
  private readonly logger = new Logger(NewFeatureController.name);

  constructor(private readonly service: NewFeatureService) {}

  @Post('test')
  @HttpCode(HttpStatus.OK)
  async testFeature(@Body(ValidationPipe) dto: { input: any }) {
    this.logger.log(`Testing feature with input: ${dto.input}`);
    return this.service.testFeature(dto);
  }
}
```

### Step 4: Create Module

```typescript
// dashboard-api/src/new-feature/new-feature.module.ts
import { Module } from '@nestjs/common';
import { NewFeatureController } from './new-feature.controller';
import { NewFeatureService } from './new-feature.service';

@Module({
  controllers: [NewFeatureController],
  providers: [NewFeatureService],
})
export class NewFeatureModule {}
```

### Step 5: Register Module

Add to `app.module.ts`:

```typescript
import { NewFeatureModule } from './new-feature/new-feature.module';

@Module({
  imports: [
    // ... other modules
    NewFeatureModule,
  ],
})
export class AppModule {}
```

### Step 6: Add Types

Add types to `core/types.ts` if needed:

```typescript
export interface NewFeatureTest {
  // Type definition
}
```

### Step 7: Create Tests

Create unit tests and E2E tests following the patterns in existing test files.

## Best Practices

### 1. Separation of Concerns

- **Controllers**: Handle HTTP, validation, logging
- **Services**: Business logic, error handling
- **Testers**: Core testing logic, can be reused

### 2. Error Handling

- Always use try-catch blocks
- Log errors with context
- Re-throw known exceptions
- Wrap unknown errors in InternalServerException

### 3. Validation

- Validate all inputs
- Use class-validator DTOs where possible
- Provide clear error messages
- Validate at service level as well as controller level

### 4. Logging

- Log all operations at appropriate levels
- Include context (user ID, resource ID, etc.)
- Log errors with stack traces
- Use structured logging

### 5. Testing

- Write unit tests for all service methods
- Test success, validation, and error cases
- Mock external dependencies
- Write E2E tests for all endpoints

### 6. Configuration

- Support provider interfaces for real integrations
- Support mock data for testing
- Maintain backward compatibility
- Document configuration options

### 7. Documentation

- Add JSDoc comments to all public methods
- Document request/response formats
- Document error cases
- Provide usage examples

## Service Examples

### Example 1: Simple Service

```typescript
@Injectable()
export class SimpleService {
  private readonly logger = new Logger(SimpleService.name);

  async processData(data: any) {
    try {
      this.validateData(data);
      // Process data
      return { success: true };
    } catch (error: any) {
      this.logger.error(`Error: ${error.message}`);
      throw new InternalServerException('Processing failed');
    }
  }

  private validateData(data: any) {
    if (!data) {
      throw new ValidationException('Data is required');
    }
  }
}
```

### Example 2: Service with Provider

```typescript
@Injectable()
export class ServiceWithProvider {
  private readonly logger = new Logger(ServiceWithProvider.name);
  private tester: SomeTester;

  constructor() {
    // Can inject provider via config in future
    this.tester = new SomeTester({
      // provider: new RealProvider(),
      mockData: { /* ... */ },
    });
  }

  async testFeature(dto: { input: any }) {
    try {
      this.validateInput(dto);
      return await this.tester.testFeature(dto.input);
    } catch (error: any) {
      this.logger.error(`Error: ${error.message}`, error.stack);
      if (error instanceof ValidationException) {
        throw error;
      }
      throw new InternalServerException('Test failed');
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Service not found**: Ensure module is registered in `app.module.ts`
2. **Type errors**: Check that types match between service and tester
3. **Provider not working**: Verify provider implements the interface correctly
4. **Tests failing**: Check that mocks are set up correctly

### Getting Help

- Review existing service implementations
- Check the API documentation
- Review test files for usage examples
- Check the implementation progress document

## Environment Configuration Testing Services

### EnvironmentConfigValidator

Validates environment variables, configuration files, and environment-specific settings.

**Location**: `services/environment-config-validator.ts`

**Usage Example**:
```typescript
import { EnvironmentConfigValidator, EnvironmentConfig } from './services/environment-config-validator';

const validator = new EnvironmentConfigValidator();

const config: EnvironmentConfig = {
  environment: 'prod',
  variables: {
    DATABASE_URL: 'postgresql://...',
    API_KEY: 'sk_live_...',
  },
  configFiles: ['./config/prod.json'],
  secrets: ['DATABASE_URL', 'API_KEY'],
};

const result = await validator.validateEnvironmentVariables(config);
console.log(`Passed: ${result.passed}, Issues: ${result.issues.length}`);
```

**Key Methods**:
- `validateEnvironmentVariables()` - Validates environment variables for security issues
- `validateConfigFileSecurity()` - Validates configuration file permissions and content
- `detectHardcodedSecrets()` - Detects hardcoded secrets in variables
- `validateEnvironmentIsolation()` - Tests environment isolation

### SecretsManagementValidator

Validates secrets storage, rotation, access logging, and injection security.

**Location**: `services/secrets-management-validator.ts`

**Usage Example**:
```typescript
import { SecretsManagementValidator, SecretsManagerConfig } from './services/secrets-management-validator';

const validator = new SecretsManagementValidator();

const config: SecretsManagerConfig = {
  type: 'vault',
  connection: {
    address: 'https://vault.example.com',
    token: 'vault-token',
  },
};

const result = await validator.validateSecretsStorage(config);
console.log(`Passed: ${result.passed}, Secrets Tested: ${result.secretsTested}`);
```

**Supported Secret Managers**:
- HashiCorp Vault
- AWS Secrets Manager
- Azure Key Vault
- GCP Secret Manager
- Kubernetes Secrets
- Environment Variables

### ConfigDriftDetector

Detects configuration changes between environments and baselines.

**Location**: `services/config-drift-detector.ts`

**Usage Example**:
```typescript
import { ConfigDriftDetector } from './services/config-drift-detector';

const detector = new ConfigDriftDetector();

// Create baseline
const baseline = await detector.createBaseline('prod', envConfig);

// Detect drift
const drift = await detector.detectDrift(baseline, currentConfig);
console.log(`Has Drift: ${drift.hasDrift}, Score: ${drift.driftScore}`);
```

### EnvironmentPolicyValidator

Validates environment-specific access policies, isolation, and promotion rules.

**Location**: `services/environment-policy-validator.ts`

**Usage Example**:
```typescript
import { EnvironmentPolicyValidator, EnvironmentPolicy } from './services/environment-policy-validator';

const validator = new EnvironmentPolicyValidator();

const policy: EnvironmentPolicy = {
  environment: 'prod',
  policies: [],
  isolationRules: [
    { fromEnvironment: 'prod', toEnvironment: 'dev', allowed: false },
  ],
  promotionRules: [
    {
      fromEnvironment: 'staging',
      toEnvironment: 'prod',
      requiredApprovals: 2,
      requiredChecks: ['security-review'],
    },
  ],
};

const result = await validator.validateEnvironmentPolicies(policy);
```

## API Security Enhancement Services

### APIVersioningTester

Tests API version deprecation, access control, backward compatibility, and migration security.

**Location**: `services/api-versioning-tester.ts`

**Usage Example**:
```typescript
import { APIVersioningTester, APIVersion } from './services/api-versioning-tester';

const tester = new APIVersioningTester();

const version: APIVersion = {
  version: 'v1',
  endpoint: '/api/v1/users',
  deprecated: true,
  deprecationDate: new Date('2024-01-01'),
  sunsetDate: new Date('2024-12-31'),
  accessControl: { requiredRoles: ['admin'] },
};

const result = await tester.testVersionDeprecation(version);
```

### APIGatewayPolicyValidator

Validates API gateway routing, authentication, rate limiting, and transformation policies.

**Location**: `services/api-gateway-policy-validator.ts`

**Supported Gateways**:
- AWS API Gateway
- Azure API Management
- Kong
- Istio
- Envoy

**Usage Example**:
```typescript
import { APIGatewayPolicyValidator, APIGatewayConfig } from './services/api-gateway-policy-validator';

const validator = new APIGatewayPolicyValidator();

const config: APIGatewayConfig = {
  type: 'aws-api-gateway',
  endpoint: 'https://api.example.com',
  policies: [/* ... */],
  routes: [/* ... */],
};

const result = await validator.validateGatewayPolicies(config);
```

### WebhookSecurityTester

Tests webhook authentication, encryption, replay attack prevention, and delivery guarantees.

**Location**: `services/webhook-security-tester.ts`

**Usage Example**:
```typescript
import { WebhookSecurityTester, WebhookConfig } from './services/webhook-security-tester';

const tester = new WebhookSecurityTester();

const config: WebhookConfig = {
  endpoint: 'https://api.example.com/webhooks',
  authentication: { type: 'signature', method: 'hmac-sha256' },
  encryption: { enabled: true, method: 'tls' },
  rateLimiting: { maxRequests: 100, windowSeconds: 60 },
};

const result = await tester.testWebhookAuthentication(config);
```

### GraphQLSecurityValidator

Tests GraphQL query depth limits, complexity limits, introspection security, and field authorization.

**Location**: `services/graphql-security-validator.ts`

**Usage Example**:
```typescript
import { GraphQLSecurityValidator, GraphQLConfig } from './services/graphql-security-validator';

const validator = new GraphQLSecurityValidator();

const config: GraphQLConfig = {
  endpoint: 'https://api.example.com/graphql',
  schema: 'type User { id: ID! name: String! }',
  maxDepth: 5,
  maxComplexity: 100,
  introspectionEnabled: false,
};

const result = await validator.testQueryDepthLimits(config);
```

### APIContractSecurityTester

Tests API contract versioning security, schema security, and contract enforcement.

**Location**: `services/api-contract-security-tester.ts`

**Usage Example**:
```typescript
import { APIContractSecurityTester, APIContract } from './services/api-contract-security-tester';

const tester = new APIContractSecurityTester();

const contract: APIContract = {
  version: '1.0.0',
  schema: { /* OpenAPI schema */ },
  endpoints: [/* ... */],
};

const result = await tester.validateContractSecurity(contract);
```

## ABAC Correctness Services

### ABACAttributeValidator

Validates ABAC attribute definitions, schemas, sources, freshness, and access controls.

**Location**: `services/abac-attribute-validator.ts`

**Usage Example**:
```typescript
import { ABACAttributeValidator, ABACAttribute } from './services/abac-attribute-validator';

const validator = new ABACAttributeValidator();

const attribute: ABACAttribute = {
  name: 'clearanceLevel',
  type: 'string',
  source: 'ldap',
  validation: [{ type: 'enum', value: ['low', 'medium', 'high'] }],
  freshness: { maxAge: 24, unit: 'hours' },
};

const result = await validator.validateAttributeDefinition(attribute);
```

### ABACCompletenessTester

Tests policy coverage for resource types, user roles, actions, and edge cases.

**Location**: `services/abac-completeness-tester.ts`

**Usage Example**:
```typescript
import { ABACCompletenessTester, CompletenessTestConfig } from './services/abac-completeness-tester';

const tester = new ABACCompletenessTester();

const config: CompletenessTestConfig = {
  resourceTypes: ['dataset', 'report'],
  userRoles: ['admin', 'researcher'],
  actions: ['read', 'write'],
  policies: [/* ABAC policies */],
};

const result = await tester.testPolicyCompleteness(config);
console.log(`Coverage: ${result.coverage.resourceTypes}%`);
```

### ABACPerformanceTester

Tests ABAC evaluation latency, caching, attribute lookup performance, and load performance.

**Location**: `services/abac-performance-tester.ts`

**Usage Example**:
```typescript
import { ABACPerformanceTester, PerformanceTestConfig } from './services/abac-performance-tester';
import { PolicyDecisionPoint } from './services/policy-decision-point';

const pdp = new PolicyDecisionPoint({ /* config */ });
const tester = new ABACPerformanceTester(pdp);

const config: PerformanceTestConfig = {
  policies: [/* ... */],
  testRequests: [/* ... */],
  loadConfig: { concurrentRequests: 10, duration: 5000 },
};

const result = await tester.testEvaluationLatency(config);
console.log(`Average Latency: ${result.averageLatency}ms`);
```

### ABACConflictTester

Detects conflicting ABAC policies and tests conflict resolution.

**Location**: `services/abac-conflict-tester.ts`

**Usage Example**:
```typescript
import { ABACConflictTester, ConflictTestConfig } from './services/abac-conflict-tester';

const tester = new ABACConflictTester(pdp);

const config: ConflictTestConfig = {
  policies: [/* ... */],
  resolutionStrategy: 'priority',
};

const result = await tester.detectPolicyConflicts(config);
console.log(`Conflicts Found: ${result.conflicts.length}`);
```

### ABACPropagationTester

Tests attribute inheritance, propagation across systems, transformation, and consistency.

**Location**: `services/abac-propagation-tester.ts`

**Usage Example**:
```typescript
import { ABACPropagationTester, PropagationTestConfig } from './services/abac-propagation-tester';

const tester = new ABACPropagationTester();

const config: PropagationTestConfig = {
  sourceSystem: 'ldap',
  targetSystems: ['api', 'database'],
  attributes: [/* ... */],
  transformationRules: [/* ... */],
};

const result = await tester.testAttributePropagation(config);
```


