import { Injectable, UnauthorizedException, ConflictException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { UsersService } from '../users/users.service';
import { User } from '../users/entities/user.entity';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { SecurityAuditLogService, SecurityAuditEventType } from '../security/audit-log.service';
import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface JwtPayload {
  sub: string;
  email: string;
  roles: string[];
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly refreshTokensFile: string;
  private refreshTokens: Map<string, { userId: string; expiresAt: Date }> = new Map();

  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly auditLogService: SecurityAuditLogService,
  ) {
    const dataDir = process.env.DATA_DIR || path.join(process.cwd(), '..', 'data');
    this.refreshTokensFile = path.join(dataDir, 'refresh-tokens.json');
    this.loadRefreshTokens();
  }

  /**
   * Load refresh tokens from file
   */
  private async loadRefreshTokens(): Promise<void> {
    try {
      const data = await fs.readFile(this.refreshTokensFile, 'utf8');
      const tokens: Array<{ token: string; userId: string; expiresAt: string }> = JSON.parse(data);
      tokens.forEach(({ token, userId, expiresAt }) => {
        const expDate = new Date(expiresAt);
        if (expDate > new Date()) {
          this.refreshTokens.set(token, { userId, expiresAt: expDate });
        }
      });
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        this.logger.error('Error loading refresh tokens:', error);
      }
    }
  }

  /**
   * Save refresh tokens to file
   */
  private async saveRefreshTokens(): Promise<void> {
    try {
      const dataDir = path.dirname(this.refreshTokensFile);
      await fs.mkdir(dataDir, { recursive: true });
      const tokens = Array.from(this.refreshTokens.entries()).map(([token, data]) => ({
        token,
        userId: data.userId,
        expiresAt: data.expiresAt.toISOString(),
      }));
      await fs.writeFile(this.refreshTokensFile, JSON.stringify(tokens, null, 2), 'utf8');
    } catch (error) {
      this.logger.error('Error saving refresh tokens:', error);
    }
  }

  /**
   * Register a new user
   */
  async register(registerDto: RegisterDto, ipAddress?: string, userAgent?: string): Promise<AuthTokens> {
    const users = await this.usersService.getAllUsers();
    const existingUser = users.find(u => u.email === registerDto.email);

    if (existingUser) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.LOGIN_FAILURE,
        action: 'register-failed',
        description: `Registration attempt with existing email: ${registerDto.email}`,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Email already exists',
      });
      throw new ConflictException('Email already exists');
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(registerDto.password, saltRounds);

    // Create user
    const newUser: User = {
      id: uuidv4(),
      email: registerDto.email,
      name: registerDto.name,
      passwordHash,
      roles: registerDto.roles || ['viewer'],
      applicationIds: registerDto.applicationIds || [],
      teamNames: registerDto.teamNames || [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    // Save user (we need to update UsersService to support this)
    await this.saveUser(newUser);

    // Generate tokens
    const tokens = await this.generateTokens(newUser);

    await this.auditLogService.log({
      type: SecurityAuditEventType.LOGIN_SUCCESS,
      action: 'register-success',
      description: `User registered: ${registerDto.email}`,
      userId: newUser.id,
      username: newUser.email,
      ipAddress,
      userAgent,
      success: true,
    });

    return tokens;
  }

  /**
   * Authenticate user and return tokens
   */
  async login(loginDto: LoginDto, ipAddress?: string, userAgent?: string): Promise<AuthTokens> {
    const users = await this.usersService.getAllUsers();
    const user = users.find(u => u.email === loginDto.email);

    if (!user) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.LOGIN_FAILURE,
        action: 'login-failed',
        description: `Login attempt with non-existent email: ${loginDto.email}`,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Invalid credentials',
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check password
    if (!user.passwordHash) {
      // For backward compatibility, if no password hash exists, reject
      await this.auditLogService.log({
        type: SecurityAuditEventType.LOGIN_FAILURE,
        action: 'login-failed',
        description: `Login attempt for user without password: ${loginDto.email}`,
        userId: user.id,
        username: user.email,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Password not set',
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    const isPasswordValid = await bcrypt.compare(loginDto.password, user.passwordHash);
    if (!isPasswordValid) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.LOGIN_FAILURE,
        action: 'login-failed',
        description: `Failed login attempt for: ${loginDto.email}`,
        userId: user.id,
        username: user.email,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Invalid password',
      });
      throw new UnauthorizedException('Invalid credentials');
    }

    // Generate tokens
    const tokens = await this.generateTokens(user);

    await this.auditLogService.log({
      type: SecurityAuditEventType.LOGIN_SUCCESS,
      action: 'login-success',
      description: `User logged in: ${loginDto.email}`,
      userId: user.id,
      username: user.email,
      ipAddress,
      userAgent,
      success: true,
    });

    return tokens;
  }

  /**
   * Refresh access token using refresh token
   */
  async refreshToken(refreshToken: string, ipAddress?: string, userAgent?: string): Promise<AuthTokens> {
    const tokenData = this.refreshTokens.get(refreshToken);
    if (!tokenData || tokenData.expiresAt < new Date()) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.TOKEN_REVOKED,
        action: 'token-refresh-failed',
        description: 'Invalid or expired refresh token',
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'Invalid refresh token',
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    const user = await this.usersService.getUserById(tokenData.userId);
    if (!user) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.TOKEN_REVOKED,
        action: 'token-refresh-failed',
        description: 'User not found for refresh token',
        userId: tokenData.userId,
        ipAddress,
        userAgent,
        success: false,
        errorMessage: 'User not found',
      });
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Generate new tokens
    const tokens = await this.generateTokens(user);

    await this.auditLogService.log({
      type: SecurityAuditEventType.TOKEN_ISSUED,
      action: 'token-refreshed',
      description: `Token refreshed for user: ${user.email}`,
      userId: user.id,
      username: user.email,
      ipAddress,
      userAgent,
      success: true,
    });

    return tokens;
  }

  /**
   * Generate access and refresh tokens
   */
  private async generateTokens(user: User): Promise<AuthTokens> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      roles: user.roles,
    };

    const accessTokenExpiresIn = parseInt(process.env.JWT_EXPIRES_IN || '3600', 10); // 1 hour default
    const refreshTokenExpiresIn = parseInt(process.env.JWT_REFRESH_EXPIRES_IN || '604800', 10); // 7 days default

    const accessToken = this.jwtService.sign(payload, {
      expiresIn: accessTokenExpiresIn,
    });

    const refreshToken = uuidv4();
    const refreshTokenExpiresAt = new Date();
    refreshTokenExpiresAt.setSeconds(refreshTokenExpiresAt.getSeconds() + refreshTokenExpiresIn);

    this.refreshTokens.set(refreshToken, {
      userId: user.id,
      expiresAt: refreshTokenExpiresAt,
    });

    // Clean up expired tokens
    this.cleanupExpiredTokens();

    // Save refresh tokens
    this.saveRefreshTokens().catch(err => this.logger.error('Failed to save refresh tokens:', err));

    return {
      accessToken,
      refreshToken,
      expiresIn: accessTokenExpiresIn,
    };
  }

  /**
   * Clean up expired refresh tokens
   */
  private cleanupExpiredTokens(): void {
    const now = new Date();
    for (const [token, data] of this.refreshTokens.entries()) {
      if (data.expiresAt < now) {
        this.refreshTokens.delete(token);
      }
    }
  }

  /**
   * Revoke refresh token (logout)
   */
  async revokeToken(refreshToken: string, userId: string, ipAddress?: string, userAgent?: string): Promise<void> {
    const tokenData = this.refreshTokens.get(refreshToken);
    if (tokenData && tokenData.userId === userId) {
      this.refreshTokens.delete(refreshToken);
      this.saveRefreshTokens().catch(err => this.logger.error('Failed to save refresh tokens:', err));

      await this.auditLogService.log({
        type: SecurityAuditEventType.TOKEN_REVOKED,
        action: 'token-revoked',
        description: 'Refresh token revoked',
        userId,
        ipAddress,
        userAgent,
        success: true,
      });
    }
  }

  /**
   * Save user (helper method to update UsersService data)
   */
  private async saveUser(user: User): Promise<void> {
    const users = await this.usersService.getAllUsers();
    const existingIndex = users.findIndex(u => u.id === user.id);
    if (existingIndex >= 0) {
      users[existingIndex] = { ...users[existingIndex], ...user, updatedAt: new Date() };
    } else {
      users.push(user);
    }

    // Save to file (we need access to the file path)
    const usersFile = path.join(process.cwd(), '..', 'data', 'users.json');
    await fs.mkdir(path.dirname(usersFile), { recursive: true });
    await fs.writeFile(usersFile, JSON.stringify(users, null, 2), 'utf-8');
  }
}

