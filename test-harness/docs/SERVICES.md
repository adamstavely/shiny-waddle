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


