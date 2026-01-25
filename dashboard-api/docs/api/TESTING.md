# Testing Guide

This guide provides comprehensive information about testing in the Heimdall Dashboard API, including unit tests, integration tests, and E2E tests.

## Table of Contents

1. [Test Structure](#test-structure)
2. [Running Tests](#running-tests)
3. [Unit Tests](#unit-tests)
4. [Integration/E2E Tests](#integratione2e-tests)
5. [Test Utilities](#test-utilities)
6. [Writing Tests](#writing-tests)
7. [Best Practices](#best-practices)

## Test Structure

The test suite is organized as follows:

```
dashboard-api/
├── src/
│   └── **/*.service.spec.ts    # Unit tests for services
├── test/
│   ├── jest-e2e.setup.ts       # E2E test setup
│   ├── jest-e2e.json           # E2E test configuration
│   ├── test-utils.ts            # Test utilities
│   └── **/*.e2e-spec.ts         # E2E tests for controllers
└── jest.config.js               # Unit test configuration
```

## Running Tests

### Unit Tests

Run all unit tests:
```bash
cd dashboard-api
npm test
```

Run tests in watch mode:
```bash
npm run test:watch
```

Run tests with coverage:
```bash
npm run test:cov
```

Run tests for a specific file:
```bash
npm test -- rls-cls.service.spec.ts
```

### E2E Tests

Run all E2E tests:
```bash
cd dashboard-api
npm run test:e2e
```

Run a specific E2E test file:
```bash
npm run test:e2e -- rls-cls.e2e-spec.ts
```

## Unit Tests

Unit tests are located alongside the services they test (e.g., `rls-cls.service.spec.ts`).

### Test Structure

Each unit test file follows this structure:

```typescript
import { Test, TestingModule } from '@nestjs/testing';
import { RLSCLSService } from './rls-cls.service';
import { RLSCLSTester } from '../../../services/rls-cls-tester';

describe('RLSCLSService', () => {
  let service: RLSCLSService;
  let tester: jest.Mocked<RLSCLSTester>;

  beforeEach(async () => {
    // Mock dependencies
    const mockTester = {
      testRLSCoverage: jest.fn(),
      testCLSCoverage: jest.fn(),
      // ... other methods
    };

    // Create testing module
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RLSCLSService,
        {
          provide: RLSCLSTester,
          useValue: mockTester,
        },
      ],
    }).compile();

    service = module.get<RLSCLSService>(RLSCLSService);
    tester = module.get(RLSCLSTester) as jest.Mocked<RLSCLSTester>;
  });

  describe('testRLSCoverage', () => {
    it('should return RLS coverage successfully', async () => {
      // Arrange
      const mockResult = { /* ... */ };
      tester.testRLSCoverage.mockResolvedValue(mockResult);

      // Act
      const result = await service.testRLSCoverage({ database: {} });

      // Assert
      expect(result).toEqual(mockResult);
      expect(tester.testRLSCoverage).toHaveBeenCalledWith({});
    });

    it('should throw ValidationException for invalid input', async () => {
      // Test validation error
    });

    it('should throw InternalServerException on service error', async () => {
      // Test service error
    });
  });
});
```

### Test Coverage

Unit tests should cover:
- ✅ Success cases
- ✅ Validation errors
- ✅ Service errors
- ✅ Edge cases

## Integration/E2E Tests

E2E tests are located in the `test/` directory and test the full request/response cycle.

### Test Setup

E2E tests use a shared setup file (`jest-e2e.setup.ts`) that creates a test NestJS application:

```typescript
import { createE2EApp } from './jest-e2e.setup';

describe('RLS/CLS Controller (e2e)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    app = await createE2EApp();
  });

  afterAll(async () => {
    await app.close();
  });

  // Tests...
});
```

### Test Structure

Each E2E test file follows this structure:

```typescript
describe('POST /api/rls-cls/test-rls-coverage', () => {
  it('should return RLS coverage with valid input', () => {
    return request(app.getHttpServer())
      .post('/api/rls-cls/test-rls-coverage')
      .send({ database: validDatabaseConfig })
      .expect(200)
      .expect((res) => {
        expect(res.body).toHaveProperty('database');
        expect(res.body).toHaveProperty('coveragePercentage');
      });
  });

  it('should return 400 with missing database', () => {
    return request(app.getHttpServer())
      .post('/api/rls-cls/test-rls-coverage')
      .send({})
      .expect(400);
  });
});
```

### Test Coverage

E2E tests should cover:
- ✅ Valid input scenarios
- ✅ Invalid input scenarios (validation errors)
- ✅ Missing required fields
- ✅ Response structure validation

## Test Utilities

### Test Utilities File

The `test/test-utils.ts` file provides reusable utilities:

```typescript
import { MockFactory, TestFixtures } from './test-utils';

// Create mock objects
const user = MockFactory.createUser({ role: 'admin' });
const database = MockFactory.createDatabaseConfig({ database: 'test_db' });
const testResult = MockFactory.createTestResult({ passed: true });

// Use fixtures
const validUser = TestFixtures.validUser;
const validDatabase = TestFixtures.validDatabaseConfig;
```

### Available Utilities

- `MockFactory.createUser(overrides)` - Create a mock user
- `MockFactory.createResource(overrides)` - Create a mock resource
- `MockFactory.createPolicy(overrides)` - Create a mock policy
- `MockFactory.createDatabaseConfig(overrides)` - Create a mock database config
- `MockFactory.createTestResult(overrides)` - Create a mock test result
- `MockFactory.createMockService(ServiceClass)` - Create a fully mocked service

## Writing Tests

### Writing Unit Tests

1. **Mock Dependencies**: Use `jest.mock()` or provide mock implementations
2. **Test Success Cases**: Verify correct behavior with valid inputs
3. **Test Validation**: Verify validation errors are thrown correctly
4. **Test Error Handling**: Verify service errors are handled correctly
5. **Use Descriptive Names**: Test names should clearly describe what is being tested

Example:
```typescript
describe('testRLSCoverage', () => {
  it('should return RLS coverage when database config is valid', async () => {
    // Success case
  });

  it('should throw ValidationException when database config is missing', async () => {
    // Validation error
  });

  it('should throw InternalServerException when tester throws error', async () => {
    // Service error
  });
});
```

### Writing E2E Tests

1. **Use Real Application**: E2E tests use the actual NestJS application
2. **Test Full Flow**: Test the complete request/response cycle
3. **Validate Responses**: Check response structure and status codes
4. **Test Error Cases**: Verify proper error responses

Example:
```typescript
describe('POST /api/rls-cls/test-rls-coverage', () => {
  it('should return 200 with valid database config', () => {
    return request(app.getHttpServer())
      .post('/api/rls-cls/test-rls-coverage')
      .send({ database: validDatabaseConfig })
      .expect(200)
      .expect((res) => {
        expect(res.body).toHaveProperty('database');
      });
  });

  it('should return 400 when database config is missing', () => {
    return request(app.getHttpServer())
      .post('/api/rls-cls/test-rls-coverage')
      .send({})
      .expect(400);
  });
});
```

## Best Practices

### 1. Test Isolation

- Each test should be independent
- Use `beforeEach` to set up fresh state
- Clean up after tests in `afterEach` or `afterAll`

### 2. Mock External Dependencies

- Mock external services and databases
- Use `jest.fn()` for function mocks
- Use `jest.mock()` for module mocks

### 3. Test Naming

- Use descriptive test names
- Follow the pattern: "should [expected behavior] when [condition]"
- Group related tests with `describe` blocks

### 4. Assertions

- Use specific assertions (`toEqual`, `toHaveProperty`)
- Test both positive and negative cases
- Verify error messages and status codes

### 5. Coverage

- Aim for high test coverage (>80%)
- Focus on critical paths and error cases
- Don't test implementation details

### 6. Performance

- Keep tests fast (<100ms per test)
- Use `beforeAll` for expensive setup
- Avoid real network calls in unit tests

## Common Patterns

### Testing Async Methods

```typescript
it('should handle async operations', async () => {
  const result = await service.asyncMethod();
  expect(result).toBeDefined();
});
```

### Testing Error Cases

```typescript
it('should throw ValidationException', async () => {
  await expect(service.method(invalidInput))
    .rejects
    .toThrow(ValidationException);
});
```

### Testing with Mocks

```typescript
it('should call mocked method', async () => {
  const mockResult = { /* ... */ };
  mockedService.method.mockResolvedValue(mockResult);

  const result = await service.method();

  expect(mockedService.method).toHaveBeenCalled();
  expect(result).toEqual(mockResult);
});
```

### Testing HTTP Endpoints

```typescript
it('should return 200 with valid input', () => {
  return request(app.getHttpServer())
    .post('/api/endpoint')
    .send(validPayload)
    .expect(200)
    .expect((res) => {
      expect(res.body).toHaveProperty('expectedField');
    });
});
```

## Debugging Tests

### Run Tests in Debug Mode

```bash
npm run test:debug
```

### Run Specific Test

```bash
npm test -- -t "should return RLS coverage"
```

### View Coverage Report

```bash
npm run test:cov
```

Coverage reports are generated in the `coverage/` directory.

## Continuous Integration

Tests are automatically run in CI/CD pipelines. Ensure all tests pass before merging:

1. Run unit tests: `npm test`
2. Run E2E tests: `npm run test:e2e`
3. Check coverage: `npm run test:cov`

## Troubleshooting

### Common Issues

1. **Tests timing out**: Increase timeout or check for hanging promises
2. **Mock not working**: Ensure mocks are set up before the test runs
3. **Type errors**: Check that mock types match the actual types
4. **E2E tests failing**: Ensure the application can start successfully

### Getting Help

- Check existing test files for examples
- Review test utilities in `test/test-utils.ts`
- Check the implementation progress document for test patterns


