/**
 * Auth Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, UnauthorizedException, ConflictException } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService, AuthTokens } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

describe('AuthController', () => {
  let controller: AuthController;
  let authService: jest.Mocked<AuthService>;

  const mockAuthTokens: AuthTokens = {
    accessToken: 'access-token-123',
    refreshToken: 'refresh-token-456',
    expiresIn: 3600,
  };

  const mockUser = {
    id: 'user-1',
    email: 'test@example.com',
    name: 'Test User',
    roles: ['user'],
  };

  const mockRequest = {
    ip: '127.0.0.1',
    connection: { remoteAddress: '127.0.0.1' },
    get: jest.fn().mockReturnValue('Mozilla/5.0'),
    user: { id: 'user-1', userId: 'user-1' },
  };

  beforeEach(async () => {
    const mockAuthService = {
      register: jest.fn(),
      login: jest.fn(),
      refreshToken: jest.fn(),
      revokeToken: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    authService = module.get(AuthService) as jest.Mocked<AuthService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('register', () => {
    const registerDto: RegisterDto = {
      email: 'newuser@example.com',
      password: 'password123',
      name: 'New User',
      roles: ['user'],
    };

    it('should register a new user successfully', async () => {
      // Arrange
      authService.register.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.register(registerDto, mockRequest as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.register).toHaveBeenCalledTimes(1);
      expect(authService.register).toHaveBeenCalledWith(
        registerDto,
        '127.0.0.1',
        'Mozilla/5.0'
      );
    });

    it('should handle registration with IP address from connection', async () => {
      // Arrange
      const requestWithoutIp = {
        connection: { remoteAddress: '192.168.1.1' },
        get: jest.fn().mockReturnValue('Chrome/91.0'),
      };
      authService.register.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.register(registerDto, requestWithoutIp as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.register).toHaveBeenCalledWith(
        registerDto,
        '192.168.1.1',
        'Chrome/91.0'
      );
    });

    it('should handle registration without IP address', async () => {
      // Arrange
      const requestWithoutIp = {
        get: jest.fn().mockReturnValue('Safari/14.0'),
      };
      authService.register.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.register(registerDto, requestWithoutIp as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.register).toHaveBeenCalledWith(
        registerDto,
        undefined,
        'Safari/14.0'
      );
    });

    it('should propagate ConflictException when email already exists', async () => {
      // Arrange
      authService.register.mockRejectedValue(
        new ConflictException('Email already exists')
      );

      // Act & Assert
      await expect(controller.register(registerDto, mockRequest as any)).rejects.toThrow(
        ConflictException
      );
      expect(authService.register).toHaveBeenCalledTimes(1);
    });
  });

  describe('login', () => {
    const loginDto: LoginDto = {
      email: 'test@example.com',
      password: 'password123',
    };

    it('should login user successfully', async () => {
      // Arrange
      authService.login.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.login(loginDto, mockRequest as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.login).toHaveBeenCalledTimes(1);
      expect(authService.login).toHaveBeenCalledWith(
        loginDto,
        '127.0.0.1',
        'Mozilla/5.0'
      );
    });

    it('should handle login with IP address from connection', async () => {
      // Arrange
      const requestWithoutIp = {
        connection: { remoteAddress: '10.0.0.1' },
        get: jest.fn().mockReturnValue('Firefox/89.0'),
      };
      authService.login.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.login(loginDto, requestWithoutIp as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.login).toHaveBeenCalledWith(
        loginDto,
        '10.0.0.1',
        'Firefox/89.0'
      );
    });

    it('should propagate UnauthorizedException when credentials are invalid', async () => {
      // Arrange
      authService.login.mockRejectedValue(
        new UnauthorizedException('Invalid credentials')
      );

      // Act & Assert
      await expect(controller.login(loginDto, mockRequest as any)).rejects.toThrow(
        UnauthorizedException
      );
      expect(authService.login).toHaveBeenCalledTimes(1);
    });
  });

  describe('refresh', () => {
    const refreshTokenDto: RefreshTokenDto = {
      refreshToken: 'refresh-token-456',
    };

    it('should refresh token successfully', async () => {
      // Arrange
      authService.refreshToken.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.refresh(refreshTokenDto, mockRequest as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.refreshToken).toHaveBeenCalledTimes(1);
      expect(authService.refreshToken).toHaveBeenCalledWith(
        'refresh-token-456',
        '127.0.0.1',
        'Mozilla/5.0'
      );
    });

    it('should handle refresh with IP address from connection', async () => {
      // Arrange
      const requestWithoutIp = {
        connection: { remoteAddress: '172.16.0.1' },
        get: jest.fn().mockReturnValue('Edge/91.0'),
      };
      authService.refreshToken.mockResolvedValue(mockAuthTokens);

      // Act
      const result = await controller.refresh(refreshTokenDto, requestWithoutIp as any);

      // Assert
      expect(result).toEqual(mockAuthTokens);
      expect(authService.refreshToken).toHaveBeenCalledWith(
        'refresh-token-456',
        '172.16.0.1',
        'Edge/91.0'
      );
    });

    it('should propagate UnauthorizedException when refresh token is invalid', async () => {
      // Arrange
      authService.refreshToken.mockRejectedValue(
        new UnauthorizedException('Invalid refresh token')
      );

      // Act & Assert
      await expect(controller.refresh(refreshTokenDto, mockRequest as any)).rejects.toThrow(
        UnauthorizedException
      );
      expect(authService.refreshToken).toHaveBeenCalledTimes(1);
    });
  });

  describe('logout', () => {
    const refreshTokenDto: RefreshTokenDto = {
      refreshToken: 'refresh-token-456',
    };

    it('should logout user successfully', async () => {
      // Arrange
      authService.revokeToken.mockResolvedValue(undefined);

      // Act
      const result = await controller.logout(refreshTokenDto, mockRequest as any);

      // Assert
      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(authService.revokeToken).toHaveBeenCalledTimes(1);
      expect(authService.revokeToken).toHaveBeenCalledWith(
        'refresh-token-456',
        'user-1',
        '127.0.0.1',
        'Mozilla/5.0'
      );
    });

    it('should use userId from req.user.userId when req.user.id is not available', async () => {
      // Arrange
      const requestWithUserId = {
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('Mozilla/5.0'),
        user: { userId: 'user-2' },
      };
      authService.revokeToken.mockResolvedValue(undefined);

      // Act
      const result = await controller.logout(refreshTokenDto, requestWithUserId as any);

      // Assert
      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(authService.revokeToken).toHaveBeenCalledWith(
        'refresh-token-456',
        'user-2',
        '127.0.0.1',
        'Mozilla/5.0'
      );
    });

    it('should handle logout without user ID', async () => {
      // Arrange
      const requestWithoutUser = {
        ip: '127.0.0.1',
        get: jest.fn().mockReturnValue('Mozilla/5.0'),
      };
      authService.revokeToken.mockResolvedValue(undefined);

      // Act
      const result = await controller.logout(refreshTokenDto, requestWithoutUser as any);

      // Assert
      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(authService.revokeToken).toHaveBeenCalledWith(
        'refresh-token-456',
        undefined,
        '127.0.0.1',
        'Mozilla/5.0'
      );
    });

    it('should handle logout with IP address from connection', async () => {
      // Arrange
      const requestWithoutIp = {
        connection: { remoteAddress: '192.168.1.100' },
        get: jest.fn().mockReturnValue('Chrome/92.0'),
        user: { id: 'user-3' },
      };
      authService.revokeToken.mockResolvedValue(undefined);

      // Act
      const result = await controller.logout(refreshTokenDto, requestWithoutIp as any);

      // Assert
      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(authService.revokeToken).toHaveBeenCalledWith(
        'refresh-token-456',
        'user-3',
        '192.168.1.100',
        'Chrome/92.0'
      );
    });
  });
});
