/**
 * IAM Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { IAMController } from './iam.controller';
import { IAMService } from './iam.service';

describe('IAMController', () => {
  let controller: IAMController;
  let service: jest.Mocked<IAMService>;

  const mockSSOConfig = {
    type: 'saml',
    enabled: true,
    endpoint: 'https://sso.example.com',
    config: {},
  } as any;

  const mockRBACConfig = {
    provider: 'okta',
    enabled: true,
    endpoint: 'https://okta.example.com',
    config: {},
  } as any;

  const mockPAMConfig = {
    provider: 'vault',
    enabled: true,
    endpoint: 'https://vault.example.com',
    authentication: {},
    config: {},
  } as any;

  const mockIdPConfig = {
    type: 'okta',
    enabled: true,
    endpoint: 'https://okta.example.com',
    authentication: {},
    config: {},
  } as any;

  beforeEach(async () => {
    const mockService = {
      createSSO: jest.fn(),
      findAllSSO: jest.fn(),
      generateSSOAuthUrl: jest.fn(),
      createRBAC: jest.fn(),
      findAllRBAC: jest.fn(),
      getUserRoles: jest.fn(),
      hasPermission: jest.fn(),
      createPAM: jest.fn(),
      findAllPAM: jest.fn(),
      getSecret: jest.fn(),
      createIdP: jest.fn(),
      findAllIdP: jest.fn(),
      authenticateUser: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [IAMController],
      providers: [
        {
          provide: IAMService,
          useValue: mockService,
        },
      ],
    }).compile();

    controller = module.get<IAMController>(IAMController);
    service = module.get(IAMService) as jest.Mocked<IAMService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('SSO', () => {
    describe('createSSO', () => {
      it('should create SSO config', async () => {
        // Arrange
        service.createSSO.mockResolvedValue(mockSSOConfig as any);

        // Act
        const result = await controller.createSSO(mockSSOConfig);

        // Assert
        expect(result).toEqual(mockSSOConfig);
        expect(service.createSSO).toHaveBeenCalledWith(mockSSOConfig);
      });
    });

    describe('findAllSSO', () => {
      it('should find all SSO configs', async () => {
        // Arrange
        service.findAllSSO.mockResolvedValue([mockSSOConfig] as any);

        // Act
        const result = await controller.findAllSSO();

        // Assert
        expect(result).toEqual([mockSSOConfig]);
        expect(service.findAllSSO).toHaveBeenCalledTimes(1);
      });
    });

    describe('generateSSOAuthUrl', () => {
      it('should generate SSO auth URL', async () => {
        // Arrange
        service.generateSSOAuthUrl.mockResolvedValue('https://auth.example.com');

        // Act
        const result = await controller.generateSSOAuthUrl('saml', 'state-1');

        // Assert
        expect(result).toEqual({ url: 'https://auth.example.com' });
        expect(service.generateSSOAuthUrl).toHaveBeenCalledWith('saml', 'state-1');
      });
    });
  });

  describe('RBAC', () => {
    describe('createRBAC', () => {
      it('should create RBAC config', async () => {
        // Arrange
        service.createRBAC.mockResolvedValue(mockRBACConfig as any);

        // Act
        const result = await controller.createRBAC(mockRBACConfig);

        // Assert
        expect(result).toEqual(mockRBACConfig);
        expect(service.createRBAC).toHaveBeenCalledWith(mockRBACConfig);
      });
    });

    describe('findAllRBAC', () => {
      it('should find all RBAC configs', async () => {
        // Arrange
        service.findAllRBAC.mockResolvedValue([mockRBACConfig] as any);

        // Act
        const result = await controller.findAllRBAC();

        // Assert
        expect(result).toEqual([mockRBACConfig]);
        expect(service.findAllRBAC).toHaveBeenCalledTimes(1);
      });
    });

    describe('getUserRoles', () => {
      it('should get user roles', async () => {
        // Arrange
        const roles = ['admin', 'user'];
        service.getUserRoles.mockResolvedValue(roles as any);

        // Act
        const result = await controller.getUserRoles('okta', 'user-1');

        // Assert
        expect(result).toEqual(roles);
        expect(service.getUserRoles).toHaveBeenCalledWith('okta', 'user-1');
      });
    });

    describe('hasPermission', () => {
      it('should check user permission', async () => {
        // Arrange
        service.hasPermission.mockResolvedValue(true);

        // Act
        const result = await controller.hasPermission('okta', 'user-1', 'resource-1', 'read');

        // Assert
        expect(result).toEqual({ hasPermission: true });
        expect(service.hasPermission).toHaveBeenCalledWith('okta', 'user-1', 'resource-1', 'read');
      });
    });
  });

  describe('PAM', () => {
    describe('createPAM', () => {
      it('should create PAM config', async () => {
        // Arrange
        service.createPAM.mockResolvedValue(mockPAMConfig as any);

        // Act
        const result = await controller.createPAM(mockPAMConfig);

        // Assert
        expect(result).toEqual(mockPAMConfig);
        expect(service.createPAM).toHaveBeenCalledWith(mockPAMConfig);
      });
    });

    describe('findAllPAM', () => {
      it('should find all PAM configs', async () => {
        // Arrange
        service.findAllPAM.mockResolvedValue([mockPAMConfig] as any);

        // Act
        const result = await controller.findAllPAM();

        // Assert
        expect(result).toEqual([mockPAMConfig]);
        expect(service.findAllPAM).toHaveBeenCalledTimes(1);
      });
    });

    describe('getSecret', () => {
      it('should get secret', async () => {
        // Arrange
        const secret = { value: 'secret-value' };
        service.getSecret.mockResolvedValue(secret as any);

        // Act
        const result = await controller.getSecret('vault', 'path/to/secret');

        // Assert
        expect(result).toEqual(secret);
        expect(service.getSecret).toHaveBeenCalledWith('vault', 'path/to/secret');
      });
    });
  });

  describe('IdP', () => {
    describe('createIdP', () => {
      it('should create IdP config', async () => {
        // Arrange
        service.createIdP.mockResolvedValue(mockIdPConfig as any);

        // Act
        const result = await controller.createIdP(mockIdPConfig);

        // Assert
        expect(result).toEqual(mockIdPConfig);
        expect(service.createIdP).toHaveBeenCalledWith(mockIdPConfig);
      });
    });

    describe('findAllIdP', () => {
      it('should find all IdP configs', async () => {
        // Arrange
        service.findAllIdP.mockResolvedValue([mockIdPConfig] as any);

        // Act
        const result = await controller.findAllIdP();

        // Assert
        expect(result).toEqual([mockIdPConfig]);
        expect(service.findAllIdP).toHaveBeenCalledTimes(1);
      });
    });

    describe('authenticateUser', () => {
      it('should authenticate user', async () => {
        // Arrange
        const authResult = { token: 'token-1' };
        service.authenticateUser.mockResolvedValue(authResult as any);

        // Act
        const result = await controller.authenticateUser('okta', {
          username: 'user',
          password: 'pass',
        });

        // Assert
        expect(result).toEqual(authResult);
        expect(service.authenticateUser).toHaveBeenCalledWith('okta', 'user', 'pass');
      });
    });
  });
});
