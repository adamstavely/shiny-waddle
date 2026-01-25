/**
 * Version Middleware Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { VersionMiddleware } from './version.middleware';
import { Request, Response, NextFunction } from 'express';
import { Injectable } from '@nestjs/common';

describe('VersionMiddleware', () => {
  let middleware: VersionMiddleware;
  let mockRequest: Partial<Request>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [VersionMiddleware],
    }).compile();

    middleware = module.get<VersionMiddleware>(VersionMiddleware);

    mockRequest = {
      path: '/api/v1/test',
      headers: {},
    };

    mockResponse = {
      setHeader: jest.fn(),
    };

    mockNext = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('use', () => {
    it('should extract version from path', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/v1/test' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect((req as any).apiVersion).toBe('v1');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Version', 'v1');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should extract version from header when path has no version', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/test', headers: { 'x-api-version': 'v2' } } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect((req as any).apiVersion).toBe('v2');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Version', 'v2');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should default to v1 when no version specified', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/test', headers: {} } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect((req as any).apiVersion).toBe('v1');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Version', 'v1');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should normalize version format (add v prefix)', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/test', headers: { 'x-api-version': '2' } } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect((req as any).apiVersion).toBe('v2');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Version', 'v2');
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should throw BadRequestException for invalid version format', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/test', headers: { 'x-api-version': 'invalid' } } as Request;

      // Act & Assert
      expect(() => {
        middleware.use(req, mockResponse as Response, mockNext);
      }).toThrow(BadRequestException);
      expect(mockNext).not.toHaveBeenCalled();
    });

    it('should add deprecated warning header for unsupported versions', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/v2/test' } as Request;

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect((req as any).apiVersion).toBe('v2');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Version', 'v2');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Deprecated', 'true');
      expect(mockResponse.setHeader).toHaveBeenCalledWith(
        'Warning',
        '299 - "This API version (v2) is deprecated. Please migrate to the latest version."',
      );
      expect(mockNext).toHaveBeenCalledTimes(1);
    });

    it('should not add deprecated warning for supported versions', () => {
      // Arrange
      const req = { ...mockRequest, path: '/api/v1/test' } as Request;
      jest.clearAllMocks(); // Clear previous calls

      // Act
      middleware.use(req, mockResponse as Response, mockNext);

      // Assert
      expect((req as any).apiVersion).toBe('v1');
      expect(mockResponse.setHeader).toHaveBeenCalledWith('X-API-Version', 'v1');
      // Check that deprecated header was not set
      const deprecatedCalls = (mockResponse.setHeader as jest.Mock).mock.calls.filter(
        call => call[0] === 'X-API-Deprecated',
      );
      expect(deprecatedCalls.length).toBe(0);
      expect(mockNext).toHaveBeenCalledTimes(1);
    });
  });
});
