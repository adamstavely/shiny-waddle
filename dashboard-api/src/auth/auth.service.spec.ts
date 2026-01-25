/**
 * Auth Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { UnauthorizedException, ConflictException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { SecurityAuditLogService, SecurityAuditEventType } from '../security/audit-log.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { User } from '../users/entities/user.entity';

// Mock dependencies
jest.mock('bcrypt');
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('AuthService', () => {
  let service: AuthService;
  let usersService: jest.Mocked<UsersService>;
  let jwtService: jest.Mocked<JwtService>;
  let auditLogService: jest.Mocked<SecurityAuditLogService>;

  const mockUser: User = {
    id: 'user-123',
    email: 'test@example.com',
    name: 'Test User',
    passwordHash: 'hashed-password',
    roles: ['viewer'],
    applicationIds: [],
    teamNames: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    // Create mock instances
    const mockUsersService = {
      getAllUsers: jest.fn(),
      getUserById: jest.fn(),
    };

    const mockJwtService = {
      sign: jest.fn(),
    };

    const mockAuditLogService = {
      log: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: JwtService,
          useValue: mockJwtService,
        },
        {
          provide: SecurityAuditLogService,
          useValue: mockAuditLogService,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService) as jest.Mocked<UsersService>;
    jwtService = module.get(JwtService) as jest.Mocked<JwtService>;
    auditLogService = module.get(SecurityAuditLogService) as jest.Mocked<SecurityAuditLogService>;
  });

  describe('register', () => {
    const registerDto: RegisterDto = {
      email: 'newuser@example.com',
      name: 'New User',
      password: 'password123',
      roles: ['viewer'],
    };

    it('should successfully register a new user', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([]);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
      jwtService.sign.mockReturnValue('mock-access-token');
      auditLogService.log.mockResolvedValue(undefined);

      // Mock fs operations
      const fs = require('fs/promises');
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);

      // Act
      const result = await service.register(registerDto, '192.168.1.1', 'test-agent');

      // Assert
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result).toHaveProperty('expiresIn');
      expect(bcrypt.hash).toHaveBeenCalledWith(registerDto.password, 10);
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.LOGIN_SUCCESS,
          action: 'register-success',
          success: true,
        })
      );
    });

    it('should throw ConflictException when email already exists', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([mockUser]);
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.register({ ...registerDto, email: mockUser.email }, '192.168.1.1', 'test-agent')
      ).rejects.toThrow(ConflictException);

      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.LOGIN_FAILURE,
          action: 'register-failed',
          success: false,
        })
      );
    });

    it('should hash password with correct salt rounds', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([]);
      (bcrypt.hash as jest.Mock).mockResolvedValue('hashed-password');
      jwtService.sign.mockReturnValue('mock-access-token');

      const fs = require('fs/promises');
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);

      // Act
      await service.register(registerDto);

      // Assert
      expect(bcrypt.hash).toHaveBeenCalledWith(registerDto.password, 10);
    });
  });

  describe('login', () => {
    const loginDto: LoginDto = {
      email: 'test@example.com',
      password: 'password123',
    };

    it('should successfully login with valid credentials', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([mockUser]);
      (bcrypt.compare as jest.Mock).mockResolvedValue(true);
      jwtService.sign.mockReturnValue('mock-access-token');
      auditLogService.log.mockResolvedValue(undefined);

      const fs = require('fs/promises');
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);

      // Act
      const result = await service.login(loginDto, '192.168.1.1', 'test-agent');

      // Assert
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result).toHaveProperty('expiresIn');
      expect(bcrypt.compare).toHaveBeenCalledWith(loginDto.password, mockUser.passwordHash);
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.LOGIN_SUCCESS,
          action: 'login-success',
          success: true,
        })
      );
    });

    it('should throw UnauthorizedException when user does not exist', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([]);
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.login(loginDto, '192.168.1.1', 'test-agent')
      ).rejects.toThrow(UnauthorizedException);

      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.LOGIN_FAILURE,
          action: 'login-failed',
          success: false,
        })
      );
    });

    it('should throw UnauthorizedException when password is invalid', async () => {
      // Arrange
      usersService.getAllUsers.mockResolvedValue([mockUser]);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.login(loginDto, '192.168.1.1', 'test-agent')
      ).rejects.toThrow(UnauthorizedException);

      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.LOGIN_FAILURE,
          action: 'login-failed',
          success: false,
        })
      );
    });

    it('should throw UnauthorizedException when user has no password hash', async () => {
      // Arrange
      const userWithoutPassword = { ...mockUser, passwordHash: undefined };
      usersService.getAllUsers.mockResolvedValue([userWithoutPassword as User]);
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.login(loginDto, '192.168.1.1', 'test-agent')
      ).rejects.toThrow(UnauthorizedException);

      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.LOGIN_FAILURE,
          action: 'login-failed',
          success: false,
        })
      );
    });
  });

  describe('refreshToken', () => {
    const refreshToken = 'valid-refresh-token';
    const expiredRefreshToken = 'expired-refresh-token';

    it('should successfully refresh token with valid refresh token', async () => {
      // Arrange
      // Mock the refreshTokens map
      const tokenData = { userId: mockUser.id, expiresAt: new Date(Date.now() + 3600000) };
      (service as any).refreshTokens.set(refreshToken, tokenData);

      usersService.getUserById.mockResolvedValue(mockUser);
      jwtService.sign.mockReturnValue('new-access-token');
      auditLogService.log.mockResolvedValue(undefined);

      const fs = require('fs/promises');
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);

      // Act
      const result = await service.refreshToken(refreshToken, '192.168.1.1', 'test-agent');

      // Assert
      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(result).toHaveProperty('expiresIn');
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.TOKEN_ISSUED,
          action: 'token-refreshed',
          success: true,
        })
      );
    });

    it('should throw UnauthorizedException when refresh token is invalid', async () => {
      // Arrange
      (service as any).refreshTokens.clear();
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.refreshToken('invalid-token', '192.168.1.1', 'test-agent')
      ).rejects.toThrow(UnauthorizedException);

      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.TOKEN_REVOKED,
          action: 'token-refresh-failed',
          success: false,
        })
      );
    });

    it('should throw UnauthorizedException when refresh token is expired', async () => {
      // Arrange
      const expiredTokenData = { userId: mockUser.id, expiresAt: new Date(Date.now() - 1000) };
      (service as any).refreshTokens.set(expiredRefreshToken, expiredTokenData);
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.refreshToken(expiredRefreshToken, '192.168.1.1', 'test-agent')
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException when user not found', async () => {
      // Arrange
      const tokenData = { userId: 'non-existent-user', expiresAt: new Date(Date.now() + 3600000) };
      (service as any).refreshTokens.set(refreshToken, tokenData);
      usersService.getUserById.mockResolvedValue(null);
      auditLogService.log.mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.refreshToken(refreshToken, '192.168.1.1', 'test-agent')
      ).rejects.toThrow(UnauthorizedException);

      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.TOKEN_REVOKED,
          action: 'token-refresh-failed',
          success: false,
        })
      );
    });
  });

  describe('revokeToken', () => {
    const refreshToken = 'valid-refresh-token';

    it('should successfully revoke token', async () => {
      // Arrange
      const tokenData = { userId: mockUser.id, expiresAt: new Date(Date.now() + 3600000) };
      (service as any).refreshTokens.set(refreshToken, tokenData);
      auditLogService.log.mockResolvedValue(undefined);

      const fs = require('fs/promises');
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);

      // Act
      await service.revokeToken(refreshToken, mockUser.id, '192.168.1.1', 'test-agent');

      // Assert
      expect((service as any).refreshTokens.has(refreshToken)).toBe(false);
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.TOKEN_REVOKED,
          action: 'token-revoked',
          success: true,
        })
      );
    });

    it('should not throw error when token does not exist', async () => {
      // Arrange
      (service as any).refreshTokens.clear();
      auditLogService.log.mockResolvedValue(undefined);

      const fs = require('fs/promises');
      fs.mkdir = jest.fn().mockResolvedValue(undefined);
      fs.writeFile = jest.fn().mockResolvedValue(undefined);

      // Act & Assert
      await expect(
        service.revokeToken('non-existent-token', mockUser.id, '192.168.1.1', 'test-agent')
      ).resolves.not.toThrow();
    });

    it('should not revoke token when userId does not match', async () => {
      // Arrange
      const tokenData = { userId: mockUser.id, expiresAt: new Date(Date.now() + 3600000) };
      (service as any).refreshTokens.set(refreshToken, tokenData);
      auditLogService.log.mockResolvedValue(undefined);

      // Act
      await service.revokeToken(refreshToken, 'different-user-id', '192.168.1.1', 'test-agent');

      // Assert
      expect((service as any).refreshTokens.has(refreshToken)).toBe(true);
    });
  });
});
