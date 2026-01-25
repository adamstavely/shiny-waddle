/**
 * Sanitize Middleware Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { SanitizeMiddleware } from './sanitize.middleware';
import { Request, Response, NextFunction } from 'express';

describe('SanitizeMiddleware', () => {
  let middleware: SanitizeMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SanitizeMiddleware],
    }).compile();

    middleware = module.get<SanitizeMiddleware>(SanitizeMiddleware);

    mockRequest = {
      query: {},
      body: {},
      params: {},
    };

    mockResponse = {};

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('use', () => {
    it('should sanitize query parameters', () => {
      // Arrange
      mockRequest.query = {
        name: '<script>alert("xss")</script>',
        value: 'test--value;',
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.query.name).not.toContain('<script>');
      expect(mockRequest.query.name).not.toContain('</script>');
      expect(mockRequest.query.value).not.toContain('--');
      expect(mockRequest.query.value).not.toContain(';');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should sanitize body parameters', () => {
      // Arrange
      mockRequest.body = {
        name: '<script>alert("xss")</script>',
        description: 'test/*comment*/value',
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.body.name).not.toContain('<script>');
      expect(mockRequest.body.name).not.toContain('</script>');
      expect(mockRequest.body.description).not.toContain('/*');
      expect(mockRequest.body.description).not.toContain('*/');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should sanitize route parameters', () => {
      // Arrange
      mockRequest.params = {
        id: 'test--id;',
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.params.id).not.toContain('--');
      expect(mockRequest.params.id).not.toContain(';');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should sanitize nested objects', () => {
      // Arrange
      mockRequest.body = {
        user: {
          name: '<script>alert("xss")</script>',
          email: 'test@example.com',
        },
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.body.user.name).not.toContain('<script>');
      expect(mockRequest.body.user.name).not.toContain('</script>');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should sanitize arrays', () => {
      // Arrange
      mockRequest.body = {
        tags: ['<script>tag1</script>', 'tag2--value'],
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.body.tags[0]).not.toContain('<script>');
      expect(mockRequest.body.tags[0]).not.toContain('</script>');
      expect(mockRequest.body.tags[1]).not.toContain('--');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should handle null and undefined values', () => {
      // Arrange
      mockRequest.query = null as any;
      mockRequest.body = undefined as any;

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should remove null bytes', () => {
      // Arrange
      mockRequest.body = {
        value: 'test\0value',
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.body.value).not.toContain('\0');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should trim whitespace', () => {
      // Arrange
      mockRequest.body = {
        value: '  test value  ',
      };

      // Act
      middleware.use(mockRequest as Request, mockResponse as Response, mockNext);

      // Assert
      expect(mockRequest.body.value).toBe('test value');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });
  });
});
