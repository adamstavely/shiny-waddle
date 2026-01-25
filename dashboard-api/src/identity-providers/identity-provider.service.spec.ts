/**
 * Identity Provider Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { IdentityProviderService } from './identity-provider.service';
import { IdentityProviderTester } from '../../heimdall-framework/services/identity-provider-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/identity-provider-tester');

describe('IdentityProviderService', () => {
  let service: IdentityProviderService;
  let mockTester: jest.Mocked<IdentityProviderTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    mockTester = {
      testADGroupMembership: jest.fn(),
      testOktaPolicySync: jest.fn(),
      testAuth0PolicySync: jest.fn(),
      testAzureADConditionalAccess: jest.fn(),
      testGCPIAMBindings: jest.fn(),
      validatePolicySynchronization: jest.fn(),
    } as any;

    // Mock the constructor
    (IdentityProviderTester as jest.Mock).mockImplementation(() => mockTester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [IdentityProviderService],
    }).compile();

    service = module.get<IdentityProviderService>(IdentityProviderService);
  });

  describe('testADGroup', () => {
    it('should successfully test AD group membership', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'AD Group Membership Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testADGroupMembership.mockResolvedValue(mockResult);

      const result = await service.testADGroup({
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        group: 'test-group',
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing user', async () => {
      await expect(
        service.testADGroup({
          user: null as any,
          group: 'test-group',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing group', async () => {
      await expect(
        service.testADGroup({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          group: '',
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testOktaPolicy', () => {
    it('should successfully test Okta policy sync', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'Okta Policy Sync Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testOktaPolicySync.mockResolvedValue(mockResult);

      const result = await service.testOktaPolicy({
        policy: {
          policyId: 'okta-policy-1',
          policyName: 'Test Policy',
          synchronized: true,
          lastSync: new Date(),
          violations: [],
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing policy', async () => {
      await expect(service.testOktaPolicy({ policy: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing policyId', async () => {
      await expect(
        service.testOktaPolicy({
          policy: {
            policyName: 'Test Policy',
            synchronized: true,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testAzureADConditionalAccess', () => {
    it('should successfully test Azure AD conditional access', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'Azure AD Conditional Access Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testAzureADConditionalAccess.mockResolvedValue(mockResult);

      const result = await service.testAzureADConditionalAccess({
        policy: {
          id: 'azure-policy-1',
          name: 'Test Policy',
          conditions: {},
          grantControls: {},
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing policy id', async () => {
      await expect(
        service.testAzureADConditionalAccess({
          policy: {
            name: 'Test Policy',
            conditions: {},
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testGCPIAMBinding', () => {
    it('should successfully test GCP IAM binding', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'GCP IAM Binding Test',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockTester.testGCPIAMBindings.mockResolvedValue(mockResult);

      const result = await service.testGCPIAMBinding({
        binding: {
          resource: 'projects/test-project',
          role: 'roles/viewer',
          members: ['user:test@example.com'],
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing binding', async () => {
      await expect(service.testGCPIAMBinding({ binding: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing resource', async () => {
      await expect(
        service.testGCPIAMBinding({
          binding: {
            role: 'roles/viewer',
            members: [],
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing role', async () => {
      await expect(
        service.testGCPIAMBinding({
          binding: {
            resource: 'projects/test-project',
            members: [],
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('validatePolicySync', () => {
    it('should successfully validate policy synchronization', async () => {
      const mockResult = {
        testType: 'access-control' as const,
        testName: 'Policy Synchronization Validation',
        passed: true,
        details: {
          synchronized: true,
          differences: [],
        },
        timestamp: new Date(),
      };

      mockTester.validatePolicySynchronization.mockResolvedValue(mockResult);

      const result = await service.validatePolicySync({
        source: { type: 'ad', config: {} },
        target: { type: 'okta', config: {} },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing source', async () => {
      await expect(
        service.validatePolicySync({
          source: null as any,
          target: { type: 'okta', config: {} },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing source type', async () => {
      await expect(
        service.validatePolicySync({
          source: { config: {} } as any,
          target: { type: 'okta', config: {} },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid source type', async () => {
      await expect(
        service.validatePolicySync({
          source: { type: 'invalid', config: {} },
          target: { type: 'okta', config: {} },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid target type', async () => {
      await expect(
        service.validatePolicySync({
          source: { type: 'ad', config: {} },
          target: { type: 'invalid', config: {} },
        }),
      ).rejects.toThrow(ValidationException);
    });
  });
});

