/**
 * Identity Lifecycle Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { IdentityLifecycleService } from './identity-lifecycle.service';
import { IdentityLifecycleTester } from '../../../services/identity-lifecycle-tester';
import { PAMTester } from '../../../services/pam-tester';
import { IdentityVerificationTester } from '../../../services/identity-verification-tester';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../services/identity-lifecycle-tester');
jest.mock('../../../services/pam-tester');
jest.mock('../../../services/identity-verification-tester');

describe('IdentityLifecycleService', () => {
  let service: IdentityLifecycleService;
  let mockLifecycleTester: jest.Mocked<IdentityLifecycleTester>;
  let mockPamTester: jest.Mocked<PAMTester>;
  let mockVerificationTester: jest.Mocked<IdentityVerificationTester>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instances
    mockLifecycleTester = {
      testOnboardingWorkflow: jest.fn(),
      testRoleChangeWorkflow: jest.fn(),
      testOffboardingWorkflow: jest.fn(),
      validateCredentialRotation: jest.fn(),
      testMFAEnforcement: jest.fn(),
    } as any;

    mockPamTester = {
      testJITAccess: jest.fn(),
      testBreakGlassAccess: jest.fn(),
    } as any;

    mockVerificationTester = {} as any;

    // Mock the constructors
    (IdentityLifecycleTester as jest.Mock).mockImplementation(() => mockLifecycleTester);
    (PAMTester as jest.Mock).mockImplementation(() => mockPamTester);
    (IdentityVerificationTester as jest.Mock).mockImplementation(() => mockVerificationTester);

    const module: TestingModule = await Test.createTestingModule({
      providers: [IdentityLifecycleService],
    }).compile();

    service = module.get<IdentityLifecycleService>(IdentityLifecycleService);
  });

  describe('testOnboarding', () => {
    it('should successfully test onboarding workflow', async () => {
      const mockResult = {
        testType: 'access-control',
        testName: 'Identity Onboarding Workflow',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockLifecycleTester.testOnboardingWorkflow.mockResolvedValue(mockResult);

      const result = await service.testOnboarding({
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing user', async () => {
      await expect(service.testOnboarding({ user: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing user id', async () => {
      await expect(
        service.testOnboarding({
          user: { email: 'test@example.com', role: 'viewer', attributes: {} } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testRoleChange', () => {
    it('should successfully test role change workflow', async () => {
      const mockResult = {
        testType: 'access-control',
        testName: 'Role Change Workflow',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockLifecycleTester.testRoleChangeWorkflow.mockResolvedValue(mockResult);

      const result = await service.testRoleChange({
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
        newRole: 'admin',
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing newRole', async () => {
      await expect(
        service.testRoleChange({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          newRole: '',
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid role', async () => {
      await expect(
        service.testRoleChange({
          user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
          newRole: 'invalid-role',
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testOffboarding', () => {
    it('should successfully test offboarding workflow', async () => {
      const mockResult = {
        testType: 'access-control',
        testName: 'Identity Offboarding Workflow',
        passed: true,
        details: {},
        timestamp: new Date(),
      };

      mockLifecycleTester.testOffboardingWorkflow.mockResolvedValue(mockResult);

      const result = await service.testOffboarding({
        user: { id: 'user-1', email: 'test@example.com', role: 'viewer', attributes: {} },
      });

      expect(result).toEqual(mockResult);
    });
  });

  describe('testJITAccess', () => {
    it('should successfully test JIT access', async () => {
      const mockResult = {
        passed: true,
        details: {},
      };

      mockPamTester.testJITAccess.mockResolvedValue(mockResult);

      const result = await service.testJITAccess({
        request: {
          userId: 'user-1',
          resource: { id: 'resource-1', type: 'dataset', attributes: {} },
          reason: 'Testing',
          duration: 60,
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing request', async () => {
      await expect(service.testJITAccess({ request: null as any })).rejects.toThrow(
        ValidationException,
      );
    });

    it('should throw ValidationException for missing userId', async () => {
      await expect(
        service.testJITAccess({
          request: {
            resource: { id: 'resource-1', type: 'dataset', attributes: {} },
            reason: 'Testing',
            duration: 60,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing resource', async () => {
      await expect(
        service.testJITAccess({
          request: {
            userId: 'user-1',
            reason: 'Testing',
            duration: 60,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('testBreakGlass', () => {
    it('should successfully test break-glass access', async () => {
      const mockResult = {
        passed: true,
        details: {},
      };

      mockPamTester.testBreakGlassAccess.mockResolvedValue(mockResult);

      const result = await service.testBreakGlass({
        request: {
          userId: 'user-1',
          resource: { id: 'resource-1', type: 'dataset', attributes: {} },
          reason: 'Emergency',
          duration: 60,
          emergency: true,
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing request', async () => {
      await expect(service.testBreakGlass({ request: null as any })).rejects.toThrow(
        ValidationException,
      );
    });
  });
});

