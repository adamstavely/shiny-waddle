/**
 * Rate Limit Middleware Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus } from '@nestjs/common';
import { RateLimitMiddleware } from './rate-limit.middleware';
import { Request, Response, NextFunction } from 'express';

describe('RateLimitMiddleware', () => {
  let middleware: RateLimitMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [RateLimitMiddleware],
    }).compile();

    middleware = module.get<RateLimitMiddleware>(RateLimitMiddleware);

    mockRequest = {
      path: '/api/test',
      method: 'GET',
      ip: '127.0.0.1',
      connection: { remoteAddress: '127.0.0.1' } as any,
    };

    mockResponse = {
      setHeader: jest.fn(),
    };

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    // Clear rate limit store
    (middleware as any).store = {};
  });

  describe('use', () => {
    it('should allow request within rate limit', () => {
      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.setHeader).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should track requests by IP when user is not authenticated', () => {
      // Arrange
      (mockRequest as any).user = undefined;

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.setHeader).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should track requests by user ID when user is authenticated', () => {
      // Arrange
      (mockRequest as any).user = { id: 'user-1' };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.setHeader).toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should throw HttpException when rate limit exceeded', () => {
      // Arrange
      const store = (middleware as any).store;
      const key = 'ip:127.0.0.1';
      store[key] = {
        count: 1000, // Exceed limit
        resetTime: Date.now() + 60000,
      };

      // Act & Assert
      expect(() => {
        middleware.use(mockRequest as Request, mockResponse as Response, mockNext);
      }).toThrow(HttpException);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should reset count after TTL expires', () => {
      // Arrange
      const store = (middleware as any).store;
      const key = 'ip:127.0.0.1';
      store[key] = {
        count: 100,
        resetTime: Date.now() - 1000, // Expired
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(store[key].count).toBe(1);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should set rate limit headers', () => {
      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', expect.any(String));
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', expect.any(String));
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-RateLimit-Reset', expect.any(String));
      expect(mockNext).toHaveBeenCalledTimes(1);
    });
  });
});
