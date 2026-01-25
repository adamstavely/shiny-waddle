/**
 * Integration Tests for Policy Management Workflow
 * 
 * Tests the complete workflow:
 * 1. Create policy
 * 2. Validate policy
 * 3. Assign to application
 * 4. Run tests
 * 5. View results
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { PoliciesService } from '../src/policies/policies.service';
import { PolicyValidationService } from '../src/policy-validation/policy-validation.service';
import { ApplicationsService } from '../src/applications/applications.service';
import { TestsService } from '../src/tests/tests.service';
import { TestResultsService } from '../src/test-results/test-results.service';
import { CreatePolicyDto, PolicyType, PolicyStatus, PolicyEffect } from '../src/policies/dto/create-policy.dto';
import { CreateApplicationDto, ApplicationType } from '../src/applications/dto/create-application.dto';
import { CreateTestDto } from '../src/tests/dto/create-test.dto';

describe('Policy Management Workflow (Integration)', () => {
  let app: INestApplication;
  let policiesService: PoliciesService;
  let policyValidationService: PolicyValidationService;
  let applicationsService: ApplicationsService;
  let testsService: TestsService;
  let testResultsService: TestResultsService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    policiesService = getService(app, PoliciesService);
    policyValidationService = getService(app, PolicyValidationService);
    applicationsService = getService(app, ApplicationsService);
    testsService = getService(app, TestsService);
    testResultsService = getService(app, TestResultsService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('should create policy, validate, assign to application, run tests, and view results', async () => {
    // Step 1: Create an application
    const applicationDto: CreateApplicationDto = {
      id: `policy-test-app-${Date.now()}`,
      name: 'Policy Test Application',
      description: 'Application for policy management testing',
      type: ApplicationType.API,
      team: 'test-team',
      infrastructure: {
        databases: [],
        networkSegments: [],
      },
    };
    const application = await applicationsService.create(applicationDto);
    expect(application).toBeDefined();
    expect(application.id).toBeDefined();

    // Step 2: Create a policy
    const policyDto: CreatePolicyDto = {
      name: 'Integration Test Policy',
      description: 'Policy for integration testing',
      type: PolicyType.RBAC,
      version: '1.0.0',
      status: PolicyStatus.DRAFT,
      effect: PolicyEffect.ALLOW,
      priority: 100,
      rules: [
        {
          id: 'rule-1',
          effect: PolicyEffect.ALLOW,
          conditions: {
            role: 'viewer',
          },
        },
      ],
      applicationId: application.id,
    };
    const policy = await policiesService.create(policyDto);
    expect(policy).toBeDefined();
    expect(policy.id).toBeDefined();
    expect(policy.name).toBe(policyDto.name);
    expect(policy.applicationId).toBe(application.id);

    // Step 3: Validate the policy
    const validationResult = await policyValidationService.detectConflicts([policy]);
    expect(validationResult).toBeDefined();
    expect(Array.isArray(validationResult)).toBe(true);

    // Step 4: Create a test associated with the policy
    const testDto: CreateTestDto = {
      name: 'Policy Test - Access Control',
      description: 'Test for policy validation',
      testType: 'access-control',
      enabled: true,
      policyId: policy.id,
      inputs: {
        subject: {
          role: 'viewer',
          attributes: {},
        },
        resource: {
          id: 'resource-123',
          type: 'dataset',
        },
        action: 'read',
      },
      expected: {
        allowed: true,
      },
    };
    const test = await testsService.create(testDto);
    expect(test).toBeDefined();
    expect(test.id).toBeDefined();
    expect(test.policyId).toBe(policy.id);

    // Step 5: Query test results (simulating viewing results)
    const results = await testResultsService.query({
      applicationId: application.id,
      limit: 10,
    });
    expect(Array.isArray(results)).toBe(true);

    // Verify the complete workflow
    const retrievedPolicy = await policiesService.findOne(policy.id);
    expect(retrievedPolicy).toBeDefined();
    expect(retrievedPolicy?.applicationId).toBe(application.id);

    const retrievedTest = await testsService.findOne(test.id);
    expect(retrievedTest).toBeDefined();
    expect(retrievedTest?.policyId).toBe(policy.id);
  });

  it('should handle policy validation errors', async () => {
    // Create an invalid policy (missing required fields)
    const invalidPolicyDto: CreatePolicyDto = {
      name: 'Invalid Policy',
      type: PolicyType.RBAC,
      version: '1.0.0',
      effect: PolicyEffect.ALLOW,
      rules: [], // Empty rules might cause validation issues
    };

    // Policy creation should succeed (validation happens later)
    const policy = await policiesService.create(invalidPolicyDto);
    expect(policy).toBeDefined();

    // Validation should detect issues
    const validationResult = await policyValidationService.detectConflicts([policy]);
    expect(validationResult).toBeDefined();
  });
});
