/**
 * User Context Interceptor Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { ExecutionContext, CallHandler } from '@nestjs/common';
import { of } from 'rxjs';
import { UserContextInterceptor } from './user-context.interceptor';
import { Request } from 'express';
import { UserContext } from '../interfaces/user-context.interface';

describe('UserContextInterceptor', () => {
  let interceptor: UserContextInterceptor;
  let mockExecutionContext: Partial<ExecutionContext>;
  let mockCallHandler: CallHandler;
  let mockRequest: Partial<Request>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [UserContextInterceptor],
    }).compile();

    interceptor = module.get<UserContextInterceptor>(UserContextInterceptor);

    mockRequest = {
      headers: {},
    };

    mockExecutionContext = {
      switchToHttp: jest.fn(() => ({
        getRequest: () => mockRequest as Request,
        getResponse: () => ({} as Response),
        getNext: () => jest.fn(),
      })) as any,
    };

    mockCallHandler = {
      handle: jest.fn(() => of({ data: 'test' })),
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('intercept', () => {
    it('should set mock user when user is not present', () => {
      // Arrange
      (mockRequest as any).user = undefined;

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user).toBeDefined();
      expect((mockRequest as any).user.id).toBe('current-user');
      expect((mockRequest as any).user.email).toBe('developer@example.com');
      expect((mockRequest as any).user.roles).toEqual(['editor']);
    });

    it('should not override existing user', () => {
      // Arrange
      const existingUser: UserContext = {
        id: 'existing-user',
        email: 'existing@example.com',
        roles: ['admin'],
      };
      (mockRequest as any).user = existingUser;

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user).toBe(existingUser);
      expect((mockRequest as any).user.id).toBe('existing-user');
    });

    it('should extract user ID from headers', () => {
      // Arrange
      (mockRequest as any).user = undefined;
      mockRequest.headers = { 'x-user-id': 'header-user-1' };

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user.id).toBe('header-user-1');
    });

    it('should extract user email from headers', () => {
      // Arrange
      (mockRequest as any).user = undefined;
      mockRequest.headers = { 'x-user-email': 'header@example.com' };

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user.email).toBe('header@example.com');
    });

    it('should extract user roles from headers', () => {
      // Arrange
      (mockRequest as any).user = undefined;
      mockRequest.headers = { 'x-user-roles': 'admin,viewer' };

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user.roles).toEqual(['admin', 'viewer']);
    });

    it('should add cyber-risk-manager role from header', () => {
      // Arrange
      (mockRequest as any).user = undefined;
      mockRequest.headers = { 'x-user-role': 'cyber-risk-manager' };

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user.roles).toContain('cyber-risk-manager');
    });

    it('should add data-steward role from header', () => {
      // Arrange
      (mockRequest as any).user = undefined;
      mockRequest.headers = { 'x-user-role': 'data-steward' };

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect((mockRequest as any).user.roles).toContain('data-steward');
    });

    it('should call next handler', () => {
      // Arrange
      (mockRequest as any).user = undefined;

      // Act
      interceptor.intercept(mockExecutionContext as ExecutionContext, mockCallHandler);

      // Assert
      expect(mockCallHandler.handle).toHaveBeenCalledTimes(1);
    });
  });
});
