/**
 * Identity Provider Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { IdentityProviderController } from './identity-provider.controller';
import { IdentityProviderService } from './identity-provider.service';

describe('IdentityProviderController', () => {
  let controller: IdentityProviderController;
  let identityProviderService: jest.Mocked<IdentityProviderService>;

  const mockTestResult = {
    passed: true,
    testType: 'idp-compliance' as const,
    testName: 'IDP Test',
    timestamp: new Date(),
    details: {},
  };

  beforeEach(async () => {
    const mockIdentityProviderService = {
      testADGroup: jest.fn(),
      testOktaPolicy: jest.fn(),
      testAuth0Policy: jest.fn(),
      testAzureADConditionalAccess: jest.fn(),
      testGCPIAMBinding: jest.fn(),
      validatePolicySync: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IdentityProviderController],
      providers: [
        {
          provide: IdentityProviderService,
          useValue: mockIdentityProviderService,
        },
      ],
    }).compile();

    controller = module.get<IdentityProviderController>(IdentityProviderController);
    identityProviderService = module.get(IdentityProviderService) as jest.Mocked<IdentityProviderService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('testADGroup', () => {
    it('should test AD group', async () => {
      // Arrange
      const dto = {
        user: { id: 'user-1', email: 'test@example.com' },
        group: 'Domain Admins',
      };
      identityProviderService.testADGroup.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testADGroup(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(identityProviderService.testADGroup).toHaveBeenCalledWith(dto);
    });
  });

  describe('testOktaPolicy', () => {
    it('should test Okta policy', async () => {
      // Arrange
      const dto = {
        policy: {
          policyId: 'policy-1',
          name: 'Test Policy',
        },
      };
      identityProviderService.testOktaPolicy.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testOktaPolicy(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(identityProviderService.testOktaPolicy).toHaveBeenCalledWith(dto);
    });
  });

  describe('testAuth0Policy', () => {
    it('should test Auth0 policy', async () => {
      // Arrange
      const dto = {
        policy: {
          id: 'policy-1',
          name: 'Test Policy',
        },
      };
      identityProviderService.testAuth0Policy.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testAuth0Policy(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(identityProviderService.testAuth0Policy).toHaveBeenCalledWith(dto);
    });
  });

  describe('testAzureADConditionalAccess', () => {
    it('should test Azure AD conditional access policy', async () => {
      // Arrange
      const dto = {
        policy: {
          id: 'policy-1',
          displayName: 'Test Policy',
        },
      };
      identityProviderService.testAzureADConditionalAccess.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testAzureADConditionalAccess(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(identityProviderService.testAzureADConditionalAccess).toHaveBeenCalledWith(dto);
    });
  });

  describe('testGCPIAMBinding', () => {
    it('should test GCP IAM binding', async () => {
      // Arrange
      const dto = {
        binding: {
          resource: 'projects/test-project',
          role: 'roles/viewer',
          members: ['user:test@example.com'],
        },
      };
      identityProviderService.testGCPIAMBinding.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.testGCPIAMBinding(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(identityProviderService.testGCPIAMBinding).toHaveBeenCalledWith(dto);
    });
  });

  describe('validatePolicySync', () => {
    it('should validate policy sync', async () => {
      // Arrange
      const dto = {
        source: {
          type: 'okta',
          policy: { id: 'policy-1' },
        },
        target: {
          type: 'auth0',
          policy: { id: 'policy-2' },
        },
      };
      identityProviderService.validatePolicySync.mockResolvedValue(mockTestResult);

      // Act
      const result = await controller.validatePolicySync(dto);

      // Assert
      expect(result).toEqual(mockTestResult);
      expect(identityProviderService.validatePolicySync).toHaveBeenCalledWith(dto);
    });
  });
});
