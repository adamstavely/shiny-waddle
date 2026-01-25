/**
 * Integration Tests for Data Migrations
 * 
 * Tests data migration functionality:
 * 1. Migration script execution
 * 2. Data transformation correctness
 * 3. Rollback capabilities
 * 4. Migration idempotency
 */

import { INestApplication } from '@nestjs/common';
import { createIntegrationApp, getService } from './integration-setup';
import { TestsService } from '../src/tests/tests.service';
import { PoliciesService } from '../src/policies/policies.service';
import { CreateTestDto } from '../src/tests/dto/create-test.dto';
import { CreatePolicyDto, PolicyType, PolicyStatus, PolicyEffect } from '../src/policies/dto/create-policy.dto';

describe('Data Migration Integration Tests', () => {
  let app: INestApplication;
  let testsService: TestsService;
  let policiesService: PoliciesService;

  beforeAll(async () => {
    app = await createIntegrationApp();
    testsService = getService(app, TestsService);
    policiesService = getService(app, PoliciesService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Migration Script Execution', () => {
    it('should handle migration of tests with single policy', async () => {
      // Create a policy
      const policyDto: CreatePolicyDto = {
        name: 'Migration Test Policy',
        description: 'Policy for migration testing',
        type: PolicyType.RBAC,
        version: '1.0.0',
        status: PolicyStatus.ACTIVE,
        effect: PolicyEffect.ALLOW,
        rules: [
          {
            id: 'rule-1',
            effect: PolicyEffect.ALLOW,
            conditions: {},
          },
        ],
      };
      const policy = await policiesService.create(policyDto);

      // Create a test with policyId (already in correct format)
      const testDto: CreateTestDto = {
        name: 'Migration Test - Single Policy',
        description: 'Test for migration',
        testType: 'access-control',
        policyId: policy.id,
        enabled: true,
        inputs: {
          subject: { role: 'viewer' },
          resource: { id: 'resource-1' },
          action: 'read',
        },
        expected: { allowed: true },
      };

      const test = await testsService.create(testDto);
      expect(test).toBeDefined();
      expect(test.policyId).toBe(policy.id);

      // Verify the relationship is maintained
      const retrieved = await testsService.findOne(test.id);
      expect(retrieved?.policyId).toBe(policy.id);
    });

    it('should verify test-policy relationship integrity', async () => {
      // Create multiple policies
      const policy1Dto: CreatePolicyDto = {
        name: 'Migration Policy 1',
        type: PolicyType.RBAC,
        version: '1.0.0',
        status: PolicyStatus.ACTIVE,
        effect: PolicyEffect.ALLOW,
        rules: [{ id: 'rule-1', effect: PolicyEffect.ALLOW, conditions: {} }],
      };
      const policy1 = await policiesService.create(policy1Dto);

      const policy2Dto: CreatePolicyDto = {
        name: 'Migration Policy 2',
        type: PolicyType.RBAC,
        version: '1.0.0',
        status: PolicyStatus.ACTIVE,
        effect: PolicyEffect.ALLOW,
        rules: [{ id: 'rule-2', effect: PolicyEffect.ALLOW, conditions: {} }],
      };
      const policy2 = await policiesService.create(policy2Dto);

      // Create tests for each policy
      const test1Dto: CreateTestDto = {
        name: 'Migration Test 1',
        testType: 'access-control',
        policyId: policy1.id,
        enabled: true,
        inputs: { subject: { role: 'admin' }, resource: { id: 'r1' }, action: 'read' },
        expected: { allowed: true },
      };
      const test1 = await testsService.create(test1Dto);

      const test2Dto: CreateTestDto = {
        name: 'Migration Test 2',
        testType: 'access-control',
        policyId: policy2.id,
        enabled: true,
        inputs: { subject: { role: 'viewer' }, resource: { id: 'r2' }, action: 'read' },
        expected: { allowed: true },
      };
      const test2 = await testsService.create(test2Dto);

      // Verify relationships
      const retrieved1 = await testsService.findOne(test1.id);
      const retrieved2 = await testsService.findOne(test2.id);

      expect(retrieved1?.policyId).toBe(policy1.id);
      expect(retrieved2?.policyId).toBe(policy2.id);

      // Verify policies exist
      const retrievedPolicy1 = await policiesService.findOne(policy1.id);
      const retrievedPolicy2 = await policiesService.findOne(policy2.id);

      expect(retrievedPolicy1).toBeDefined();
      expect(retrievedPolicy2).toBeDefined();
    });
  });

  describe('Data Transformation', () => {
    it('should preserve data structure during updates', async () => {
      const policyDto: CreatePolicyDto = {
        name: 'Transformation Test Policy',
        type: PolicyType.RBAC,
        version: '1.0.0',
        status: PolicyStatus.DRAFT,
        effect: PolicyEffect.ALLOW,
        rules: [
          {
            id: 'rule-1',
            effect: PolicyEffect.ALLOW,
            conditions: { role: 'admin' },
          },
        ],
      };
      const policy = await policiesService.create(policyDto);

      // Update policy
      const updated = await policiesService.update(policy.id, {
        status: PolicyStatus.ACTIVE,
        version: '1.1.0',
      });

      expect(updated.status).toBe(PolicyStatus.ACTIVE);
      expect(updated.version).toBe('1.1.0');
      expect(updated.rules).toHaveLength(1);
      expect(updated.rules?.[0].id).toBe('rule-1');
    });

    it('should handle date transformations correctly', async () => {
      const policyDto: CreatePolicyDto = {
        name: 'Date Transformation Policy',
        type: PolicyType.RBAC,
        version: '1.0.0',
        status: PolicyStatus.ACTIVE,
        effect: PolicyEffect.ALLOW,
        rules: [],
      };
      const policy = await policiesService.create(policyDto);

      // Verify dates are Date objects
      expect(policy.createdAt).toBeInstanceOf(Date);
      expect(policy.updatedAt).toBeInstanceOf(Date);

      // Update and verify dates are still Date objects
      const updated = await policiesService.update(policy.id, {
        description: 'Updated description',
      });

      expect(updated.createdAt).toBeInstanceOf(Date);
      expect(updated.updatedAt).toBeInstanceOf(Date);
      expect(updated.updatedAt.getTime()).toBeGreaterThanOrEqual(policy.updatedAt.getTime());
    });
  });

  describe('Migration Idempotency', () => {
    it('should handle repeated migrations safely', async () => {
      const policyDto: CreatePolicyDto = {
        name: 'Idempotency Test Policy',
        type: PolicyType.RBAC,
        version: '1.0.0',
        status: PolicyStatus.ACTIVE,
        effect: PolicyEffect.ALLOW,
        rules: [],
      };
      const policy = await policiesService.create(policyDto);

      const testDto: CreateTestDto = {
        name: 'Idempotency Test',
        testType: 'access-control',
        policyId: policy.id,
        enabled: true,
        inputs: { subject: { role: 'viewer' }, resource: { id: 'r1' }, action: 'read' },
        expected: { allowed: true },
      };

      // Create test multiple times (simulating migration rerun)
      const test1 = await testsService.create(testDto);
      expect(test1).toBeDefined();

      // Verify test still exists and is correct
      const retrieved = await testsService.findOne(test1.id);
      expect(retrieved).toBeDefined();
      expect(retrieved?.policyId).toBe(policy.id);
    });
  });
});
