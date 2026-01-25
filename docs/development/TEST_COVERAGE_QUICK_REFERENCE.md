# Test Coverage Expansion - Quick Reference

## Current State
- **Unit Tests:** 8/58 services (14%)
- **E2E Tests:** 9 controller files
- **Integration Tests:** Limited
- **Frontend Tests:** None

## Target State
- **Unit Tests:** 80%+ coverage (46/58 services)
- **E2E Tests:** 20+ files covering all endpoints
- **Integration Tests:** 5+ major workflows
- **Frontend Tests:** 70%+ component coverage, 10+ E2E flows

## Timeline: 22 Weeks (5.5 months)

### Phase 1: Foundation (Weeks 1-2)
- Set up test infrastructure
- Configure frontend testing tools
- Create test utilities

### Phase 2: Unit Tests (Weeks 3-8)
- **Weeks 3-4:** 10 priority services
- **Weeks 5-6:** 28 secondary services
- **Week 7:** 50 controllers
- **Week 8:** Utilities & middleware

### Phase 3: Integration Tests (Weeks 9-12)
- Multi-service workflows
- Database integration
- External service mocks

### Phase 4: E2E Expansion (Weeks 13-16)
- Authentication flows
- Complex workflows
- Complete endpoint coverage
- Error scenarios

### Phase 5: Frontend Tests (Weeks 17-20)
- Component tests (50+ components)
- Page tests (20+ pages)
- E2E flows (10+ flows)

### Phase 6: CI/CD Integration (Weeks 21-22)
- CI/CD test integration
- Coverage thresholds
- Quality gates

## Priority Services (Start Here)

1. `auth.service.ts`
2. `policies.service.ts`
3. `tests.service.ts`
4. `test-suites.service.ts`
5. `test-harnesses.service.ts`
6. `test-batteries.service.ts`
7. `applications.service.ts`
8. `compliance.service.ts`
9. `violations.service.ts`
10. `users.service.ts`

## Quick Commands

```bash
# Run unit tests
cd dashboard-api && npm test

# Run with coverage
cd dashboard-api && npm run test:cov

# Run E2E tests
cd dashboard-api && npm run test:e2e

# Run frontend tests (after setup)
cd dashboard-frontend && npm run test

# Run frontend E2E (after setup)
cd dashboard-frontend && npm run test:e2e
```

## Test Standards

### Unit Test Template
```typescript
describe('ServiceName', () => {
  let service: ServiceName;
  let mockDependency: jest.Mocked<Dependency>;

  beforeEach(async () => {
    // Setup
  });

  describe('methodName', () => {
    it('should [expected] when [condition]', async () => {
      // Arrange, Act, Assert
    });
  });
});
```

### Coverage Requirements
- ✅ Success cases
- ✅ Validation errors
- ✅ Service errors
- ✅ Edge cases

## Success Metrics
- **Coverage:** 80%+ overall
- **Execution Time:** < 5 min (unit), < 15 min (E2E)
- **Flaky Rate:** < 1%
- **CI/CD:** All tests pass before merge
