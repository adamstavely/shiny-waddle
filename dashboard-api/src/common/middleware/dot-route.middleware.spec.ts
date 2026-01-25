/**
 * Dot Route Middleware Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { DotRouteMiddleware } from './dot-route.middleware';
import { Request, Response, NextFunction } from 'express';

describe('DotRouteMiddleware', () => {
  let middleware: DotRouteMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [DotRouteMiddleware],
    }).compile();

    middleware = module.get<DotRouteMiddleware>(DotRouteMiddleware);

    mockRequest = {
      path: '/api/tests/test.idp.service_conforms_to_golden_template',
    };

    mockResponse = {};

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('use', () => {
    it('should call next for API test routes with dots', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/tests/test.idp.service_conforms_to_golden_template' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should call next for v1 API test routes with dots', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/v1/tests/test.idp.service_conforms_to_golden_template' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should call next for routes without dots', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/tests/test-1' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should call next for non-test routes', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/policies/policy-1' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should call next for routes ending with known file extensions', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/tests/test.json' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(1);
    });
  });
});
