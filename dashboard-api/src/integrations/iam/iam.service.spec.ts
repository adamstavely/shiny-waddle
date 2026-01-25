/**
 * IAM Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { IAMService } from './iam.service';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock dependencies
jest.mock('fs/promises');

describe('IAMService', () => {
  let service: IAMService;

  const mockSSOConfig = {
    type: 'saml' as const,
    enabled: true,
    endpoint: 'https://sso.example.com',
    authentication: {},
  };

  const mockRBACConfig = {
    provider: 'okta' as const,
    enabled: true,
    endpoint: 'https://okta.example.com',
    authentication: {},
  };

  const mockPAMConfig = {
    provider: 'hashicorp-vault' as const,
    enabled: true,
    endpoint: 'https://vault.example.com',
    authentication: {
      type: 'basic' as const,
      credentials: {},
    },
  };

  const mockIdPConfig = {
    type: 'ldap' as const,
    enabled: true,
    endpoint: 'ldap://ldap.example.com',
    authentication: {
      type: 'basic' as const,
      credentials: {},
    },
  };

  beforeEach(async () => {
    (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT')); // File doesn't exist by default
    
    const module: TestingModule = await Test.createTestingModule({
      providers: [IAMService],
    }).compile();

    service = module.get<IAMService>(IAMService);
    
    // Wait for async loadConfig to complete
    await new Promise(resolve => setImmediate(resolve));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('SSO', () => {
    it('should create SSO config', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.createSSO(mockSSOConfig);

      // Assert
      expect(result).toEqual(mockSSOConfig);
    });

    it('should find all SSO configs', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [mockSSOConfig],
        rbac: [],
        pam: [],
        idp: [],
      }));
      await (service as any).loadConfig();

      // Act
      const result = await service.findAllSSO();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(mockSSOConfig);
    });

    it('should generate SSO auth URL', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [mockSSOConfig],
        rbac: [],
        pam: [],
        idp: [],
      }));
      await (service as any).loadConfig();
      (service as any).iamIntegration = {
        getSSO: jest.fn(() => ({
          config: mockSSOConfig,
          generateSAMLAuthUrl: jest.fn(() => 'https://sso.example.com/auth'),
          generateOIDCAuthUrl: jest.fn(() => 'https://sso.example.com/oidc'),
        })),
      };

      // Act
      const result = await service.generateSSOAuthUrl('saml');

      // Assert
      expect(result).toBe('https://sso.example.com/auth');
    });

    it('should throw NotFoundException when SSO not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.generateSSOAuthUrl('saml')).rejects.toThrow(NotFoundException);
    });
  });

  describe('RBAC', () => {
    it('should create RBAC config', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.createRBAC(mockRBACConfig);

      // Assert
      expect(result).toEqual(mockRBACConfig);
    });

    it('should find all RBAC configs', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [mockRBACConfig],
        pam: [],
        idp: [],
      }));
      await (service as any).loadConfig();

      // Act
      const result = await service.findAllRBAC();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(mockRBACConfig);
    });

    it('should get user roles', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [mockRBACConfig],
        pam: [],
        idp: [],
      }));
      await (service as any).loadConfig();
      (service as any).iamIntegration = {
        getRBAC: jest.fn(() => ({
          getUserRoles: jest.fn().mockResolvedValue([
            { id: 'role-1', name: 'Admin' },
            { id: 'role-2', name: 'User' },
          ]),
        })),
      };

      // Act
      const result = await service.getUserRoles('okta', 'user-1');

      // Assert
      expect(result).toHaveLength(2);
      expect(result[0].name).toBe('Admin');
    });

    it('should check user permission', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [mockRBACConfig],
        pam: [],
        idp: [],
      }));
      await (service as any).loadConfig();
      (service as any).iamIntegration = {
        getRBAC: jest.fn(() => ({
          hasPermission: jest.fn().mockResolvedValue(true),
        })),
      };

      // Act
      const result = await service.hasPermission('okta', 'user-1', 'resource-1', 'read');

      // Assert
      expect(result).toBe(true);
    });

    it('should throw NotFoundException when RBAC not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.getUserRoles('okta', 'user-1')).rejects.toThrow(NotFoundException);
    });
  });

  describe('PAM', () => {
    it('should create PAM config', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.createPAM(mockPAMConfig);

      // Assert
      expect(result).toEqual(mockPAMConfig);
    });

    it('should find all PAM configs', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [],
        pam: [mockPAMConfig],
        idp: [],
      }));
      await (service as any).loadConfig();

      // Act
      const result = await service.findAllPAM();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(mockPAMConfig);
    });

    it('should get secret from PAM', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [],
        pam: [mockPAMConfig],
        idp: [],
      }));
      await (service as any).loadConfig();
      (service as any).iamIntegration = {
        getPAM: jest.fn(() => ({
          getSecret: jest.fn().mockResolvedValue({
            value: 'secret-value',
            metadata: { version: 1 },
          }),
        })),
      };

      // Act
      const result = await service.getSecret('vault', 'secret/path');

      // Assert
      expect(result.value).toBe('secret-value');
      expect(result.metadata?.version).toBe(1);
    });

    it('should throw NotFoundException when PAM not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.getSecret('vault', 'secret/path')).rejects.toThrow(NotFoundException);
    });
  });

  describe('IdP', () => {
    it('should create IdP config', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.createIdP(mockIdPConfig);

      // Assert
      expect(result).toEqual(mockIdPConfig);
    });

    it('should find all IdP configs', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [],
        pam: [],
        idp: [mockIdPConfig],
      }));
      await (service as any).loadConfig();

      // Act
      const result = await service.findAllIdP();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(mockIdPConfig);
    });

    it('should authenticate user', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [],
        pam: [],
        idp: [mockIdPConfig],
      }));
      await (service as any).loadConfig();
      (service as any).iamIntegration = {
        getIdP: jest.fn(() => ({
          authenticateUser: jest.fn().mockResolvedValue({
            success: true,
            user: { 
              id: 'user-1', 
              email: 'test@example.com', 
              name: 'Test User',
              roles: [],
              groups: [],
              attributes: {},
            },
          }),
        })),
      };

      // Act
      const result = await service.authenticateUser('ldap', 'testuser', 'password');

      // Assert
      expect(result.success).toBe(true);
      expect(result.user?.id).toBe('user-1');
      expect(result.user?.email).toBe('test@example.com');
    });

    it('should handle authentication failure', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify({
        sso: [],
        rbac: [],
        pam: [],
        idp: [mockIdPConfig],
      }));
      await (service as any).loadConfig();
      (service as any).iamIntegration = {
        getIdP: jest.fn(() => ({
          authenticateUser: jest.fn().mockResolvedValue({
            success: false,
            error: 'Invalid credentials',
          }),
        })),
      };

      // Act
      const result = await service.authenticateUser('ldap', 'testuser', 'wrongpassword');

      // Assert
      expect(result.success).toBe(false);
      expect(result.error).toBe('Invalid credentials');
    });

    it('should throw NotFoundException when IdP not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.authenticateUser('ldap', 'testuser', 'password')).rejects.toThrow(NotFoundException);
    });
  });
});
