/**
 * HTTPS Redirect Middleware Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpsRedirectMiddleware } from './https-redirect.middleware';
import { Request, Response, NextFunction } from 'express';

describe('HttpsRedirectMiddleware', () => {
  let middleware: HttpsRedirectMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [HttpsRedirectMiddleware],
    }).compile();

    middleware = module.get<HttpsRedirectMiddleware>(HttpsRedirectMiddleware);

    mockRequest = {
      secure: false,
      headers: {},
      get: jest.fn(),
      originalUrl: '/api/test',
    };

    mockResponse = {
      redirect: jest.fn(),
      setHeader: jest.fn(),
    };

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
    delete process.env.NODE_ENV;
  });

  describe('use', () => {
    it('should redirect to HTTPS in production when request is HTTP', () => {
      // Arrange
      process.env.NODE_ENV = 'production';
      const req = {
        ...mockRequest,
        secure: false,
        headers: {},
        get: jest.fn((name: string) => {
          if (name === 'host') return 'example.com';
          return undefined;
        }) as any,
      } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.redirect).toHaveBeenCalledWith(301, 'https://example.com/api/test');
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should not redirect in development', () => {
      // Arrange
      process.env.NODE_ENV = 'development';
      const req = { ...mockRequest, secure: false } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.redirect).not.toHaveBeenCalled();
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should not redirect when already HTTPS', () => {
      // Arrange
      process.env.NODE_ENV = 'production';
      const req = { ...mockRequest, secure: true } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.redirect).not.toHaveBeenCalled();
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload',
      );
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should not redirect when x-forwarded-proto is https', () => {
      // Arrange
      process.env.NODE_ENV = 'production';
      const req = { ...mockRequest, secure: false, headers: { 'x-forwarded-proto': 'https' } } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.redirect).not.toHaveBeenCalled();
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload',
      );
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should not redirect when x-forwarded-ssl is on', () => {
      // Arrange
      process.env.NODE_ENV = 'production';
      const req = { ...mockRequest, secure: false, headers: { 'x-forwarded-ssl': 'on' } } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.redirect).not.toHaveBeenCalled();
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload',
      );
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should set HSTS header in production', () => {
      // Arrange
      process.env.NODE_ENV = 'production';
      const req = { ...mockRequest, secure: true } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Strict-Transport-Security',
        'max-age=31536000; includeSubDomains; preload',
      );
      expect(mockNext).toHaveBeenCalledTimes(1);
    });
  });
});
