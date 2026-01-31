/**
 * Security Gates Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { SecurityGatesService } from './security-gates.service';
import { CICDSecurityGates } from '../../../heimdall-framework/services/cicd-security-gates';
import { ValidationException, InternalServerException } from '../common/exceptions/business.exception';

// Mock the dependencies
jest.mock('../../../heimdall-framework/services/cicd-security-gates');

describe('SecurityGatesService', () => {
  let service: SecurityGatesService;
  let mockGates: jest.Mocked<CICDSecurityGates>;

  beforeEach(async () => {
    // Reset mocks
    jest.clearAllMocks();

    // Create mock instance
    mockGates = {
      validatePreMergePolicies: jest.fn(),
      checkSecurityGates: jest.fn(),
    } as any;

    // Mock the constructor
    (CICDSecurityGates as jest.Mock).mockImplementation(() => mockGates);

    const module: TestingModule = await Test.createTestingModule({
      providers: [SecurityGatesService],
    }).compile();

    service = module.get<SecurityGatesService>(SecurityGatesService);
  });

  describe('validatePreMerge', () => {
    it('should successfully validate pre-merge policies', async () => {
      const mockResult = {
        passed: true,
        gates: [],
        findings: [],
        riskScore: 0.5,
        message: 'All pre-merge policy checks passed',
      };

      mockGates.validatePreMergePolicies.mockResolvedValue(mockResult);

      const result = await service.validatePreMerge({
        pr: {
          id: 'pr-1',
          number: 1,
          branch: 'feature-branch',
          baseBranch: 'main',
          files: [],
          author: 'test-user',
        },
        policies: [
          { id: 'policy-1', name: 'Policy 1', description: 'Test policy description', effect: 'allow', conditions: [] },
        ],
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing PR', async () => {
      await expect(
        service.validatePreMerge({
          pr: null as any,
          policies: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing PR id', async () => {
      await expect(
        service.validatePreMerge({
          pr: {
            number: 1,
            branch: 'feature-branch',
            baseBranch: 'main',
            files: [],
            author: 'test-user',
          } as any,
          policies: [],
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing policies array', async () => {
      await expect(
        service.validatePreMerge({
          pr: {
            id: 'pr-1',
            number: 1,
            branch: 'feature-branch',
            baseBranch: 'main',
            files: [],
            author: 'test-user',
          },
          policies: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });
  });

  describe('checkGates', () => {
    it('should successfully check security gates', async () => {
      const mockResult = {
        passed: true,
        gates: [],
        findings: [],
        riskScore: 0.3,
        message: 'All security gates passed',
      };

      mockGates.checkSecurityGates.mockResolvedValue(mockResult);

      const result = await service.checkGates({
        pr: {
          id: 'pr-1',
          number: 1,
          branch: 'feature-branch',
          baseBranch: 'main',
          files: [],
          author: 'test-user',
        },
        config: {
          severityThreshold: 'high',
          failOnThreshold: true,
          requirePolicies: true,
          scanIAC: true,
          scanContainers: true,
          validateK8sRBAC: true,
        },
      });

      expect(result).toEqual(mockResult);
    });

    it('should throw ValidationException for missing PR', async () => {
      await expect(
        service.checkGates({
          pr: null as any,
          config: {
            severityThreshold: 'high',
            failOnThreshold: true,
            requirePolicies: true,
            scanIAC: true,
            scanContainers: true,
            validateK8sRBAC: true,
          },
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing config', async () => {
      await expect(
        service.checkGates({
          pr: {
            id: 'pr-1',
            number: 1,
            branch: 'feature-branch',
            baseBranch: 'main',
            files: [],
            author: 'test-user',
          },
          config: null as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for missing severity threshold', async () => {
      await expect(
        service.checkGates({
          pr: {
            id: 'pr-1',
            number: 1,
            branch: 'feature-branch',
            baseBranch: 'main',
            files: [],
            author: 'test-user',
          },
          config: {
            failOnThreshold: true,
            requirePolicies: true,
            scanIAC: true,
            scanContainers: true,
            validateK8sRBAC: true,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should throw ValidationException for invalid severity threshold', async () => {
      await expect(
        service.checkGates({
          pr: {
            id: 'pr-1',
            number: 1,
            branch: 'feature-branch',
            baseBranch: 'main',
            files: [],
            author: 'test-user',
          },
          config: {
            severityThreshold: 'invalid',
            failOnThreshold: true,
            requirePolicies: true,
            scanIAC: true,
            scanContainers: true,
            validateK8sRBAC: true,
          } as any,
        }),
      ).rejects.toThrow(ValidationException);
    });

    it('should accept valid severity thresholds', async () => {
      const mockResult = {
        passed: true,
        gates: [],
        findings: [],
        riskScore: 0.3,
        message: 'All security gates passed',
      };
      mockGates.checkSecurityGates.mockResolvedValue(mockResult);

      const validSeverities = ['low', 'medium', 'high', 'critical'];
      for (const severity of validSeverities) {
        await expect(
          service.checkGates({
            pr: {
              id: 'pr-1',
              number: 1,
              branch: 'feature-branch',
              baseBranch: 'main',
              files: [],
              author: 'test-user',
            },
            config: {
              severityThreshold: severity as any,
              failOnThreshold: true,
              requirePolicies: true,
              scanIAC: true,
              scanContainers: true,
              validateK8sRBAC: true,
            },
          }),
        ).resolves.toEqual(mockResult);
      }
    });
  });
});

