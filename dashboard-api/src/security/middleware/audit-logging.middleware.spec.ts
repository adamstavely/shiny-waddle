/**
 * Audit Logging Middleware Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { AuditLoggingMiddleware } from './audit-logging.middleware';
import { SecurityAuditLogService, SecurityAuditEventType } from '../audit-log.service';
import { AppLogger } from '../../common/services/logger.service';
import { Request, Response, NextFunction } from 'express';

describe('AuditLoggingMiddleware', () => {
  let middleware: AuditLoggingMiddleware;
  let auditLogService: jest.Mocked<SecurityAuditLogService>;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const mockAuditLogService = {
      log: jest.fn().mockResolvedValue(undefined),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuditLoggingMiddleware,
        {
          provide: SecurityAuditLogService,
          useValue: mockAuditLogService,
        },
        {
          provide: AppLogger,
          useValue: {
            error: jest.fn(),
          },
        },
      ],
    }).compile();

    middleware = module.get<AuditLoggingMiddleware>(AuditLoggingMiddleware);
    auditLogService = module.get(SecurityAuditLogService) as jest.Mocked<SecurityAuditLogService>;
    
    // Mock the logger instance
    (middleware as any).logger = {
      error: jest.fn(),
    };

    mockRequest = {
      method: 'POST',
      path: '/api/test',
      ip: '127.0.0.1',
      headers: {},
      get: jest.fn((name: string) => {
        if (name === 'user-agent') return 'test-agent';
        if (name === 'host') return 'example.com';
        return undefined;
      }) as any,
      originalUrl: '/api/test',
    };

    mockResponse = {
      statusCode: 200,
      send: jest.fn(function (this: Response, body: any) {
        return this;
      }),
      setHeader: jest.fn(),
    };

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('use', () => {
    it('should add request ID to headers', () => {
      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.headers['x-request-id']).toBeDefined();
      expect(mockResponse.setHeader).toHaveBeenCalledWith('x-request-id', expect.any(String));
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should log write operations', async () => {
      // Arrange
      const req = { ...mockRequest, method: 'POST', path: '/api/test' } as Request;
      (req as any).user = { id: 'user-1', email: 'test@example.com' };

      // Act
      middleware.use(req, mockResponse as Response, mockNext);
      // Trigger the wrapped send function
      (mockResponse.send as jest.Mock).call(mockResponse, { success: true });
      await new Promise(resolve => setImmediate(resolve)); // Wait for async logging

      // Assert
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.DATA_WRITE,
          action: 'POST /api/test',
        }),
      );
    });

    it('should log read operations for sensitive paths', async () => {
      // Arrange
      const req = { ...mockRequest, method: 'GET', path: '/api/secrets' } as Request;
      (req as any).user = { id: 'user-1', email: 'test@example.com' };

      // Act
      middleware.use(req, mockResponse as Response, mockNext);
      // Trigger the wrapped send function for GET requests
      (mockResponse.send as jest.Mock).call(mockResponse, { data: 'secrets' });
      await new Promise(resolve => setImmediate(resolve)); // Wait for async logging

      // Assert
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          type: SecurityAuditEventType.DATA_READ,
          action: 'GET /api/secrets',
        }),
      );
    });

    it('should not log read operations for non-sensitive paths', async () => {
      // Arrange
      const req = { ...mockRequest, method: 'GET', path: '/api/policies' } as Request;
      (req as any).user = { id: 'user-1', email: 'test@example.com' };

      // Act
      middleware.use(req, mockResponse as Response, mockNext);
      // Trigger the wrapped send function
      (mockResponse.send as jest.Mock).call(mockResponse, { data: 'policies' });
      await new Promise(resolve => setImmediate(resolve)); // Wait for async logging

      // Assert
      expect(auditLogService.log).not.toHaveBeenCalled();
    });

    it('should capture response status code', async () => {
      // Arrange
      (mockRequest as any).user = { id: 'user-1', email: 'test@example.com' };
      mockRequest.method = 'POST';
      mockResponse.statusCode = 201;

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);
      (mockResponse.send as jest.Mock).call(mockResponse, { success: true });
      await new Promise(resolve => setImmediate(resolve)); // Wait for async logging

      // Assert
      expect(auditLogService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          responseCode: 201,
          success: true,
        }),
      );
    });

    it('should handle errors gracefully', async () => {
      // Arrange
      const req = { ...mockRequest, method: 'POST', path: '/api/test' } as Request;
      (req as any).user = { id: 'user-1', email: 'test@example.com' };
      auditLogService.log.mockRejectedValue(new Error('Logging failed'));
      const loggerErrorSpy = jest.spyOn((middleware as any).logger, 'error').mockImplementation();

      // Act
      middleware.use(req, mockResponse as Response, mockNext);
      (mockResponse.send as jest.Mock).call(mockResponse, { success: true });
      await new Promise(resolve => setImmediate(resolve)); // Wait for async logging

      // Assert - Should not throw, error should be handled internally
      expect(mockNext).toHaveBeenCalledTimes(1);
      expect(loggerErrorSpy).toHaveBeenCalled();
      loggerErrorSpy.mockRestore();
    });
  });
});
