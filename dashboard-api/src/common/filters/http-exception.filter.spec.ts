/**
 * HTTP Exception Filter Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpException, HttpStatus, BadRequestException } from '@nestjs/common';
import { AllExceptionsFilter } from './http-exception.filter';
import { ArgumentsHost } from '@nestjs/common';
import { Request, Response } from 'express';

describe('AllExceptionsFilter', () => {
  let filter: AllExceptionsFilter;
  let mockArgumentsHost: Partial<ArgumentsHost>;
  let mockResponse: Partial<Response>;
  let mockRequest: Partial<Request>;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AllExceptionsFilter],
    }).compile();

    filter = module.get<AllExceptionsFilter>(AllExceptionsFilter);

    mockRequest = {
      url: '/api/test',
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };

    mockArgumentsHost = {
      switchToHttp: jest.fn(() => ({
        getResponse: () => mockResponse as Response,
        getRequest: () => mockRequest as Request,
        getNext: () => jest.fn(),
      })) as any,
    };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('catch', () => {
    it('should handle HttpException with string message', () => {
      // Arrange
      const exception = new HttpException('Bad Request', HttpStatus.BAD_REQUEST);

      // Act
      filter.catch(exception, mockArgumentsHost as ArgumentsHost);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
      expect(mockResponse.json).toHaveBeenCalledWith({
        statusCode: HttpStatus.BAD_REQUEST,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Bad Request',
        details: null,
        timestamp: expect.any(String),
        path: '/api/test',
      });
    });

    it('should handle HttpException with object response', () => {
      // Arrange
      const exception = new BadRequestException({
        message: 'Validation failed',
        code: 'VALIDATION_ERROR',
        details: { field: 'email' },
      });

      // Act
      filter.catch(exception, mockArgumentsHost as ArgumentsHost);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.BAD_REQUEST);
      const callArgs = (mockResponse.json as jest.Mock).mock.calls[0][0];
      expect(callArgs.statusCode).toBe(HttpStatus.BAD_REQUEST);
      expect(callArgs.code).toBe('VALIDATION_ERROR');
      expect(callArgs.message).toBe('Validation failed');
      expect(callArgs.details).toEqual({ field: 'email' });
      expect(callArgs.timestamp).toBeDefined();
      expect(callArgs.path).toBe('/api/test');
    });

    it('should handle generic Error', () => {
      // Arrange
      const exception = new Error('Something went wrong');

      // Act
      filter.catch(exception, mockArgumentsHost as ArgumentsHost);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(mockResponse.json).toHaveBeenCalledWith({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Something went wrong',
        details: null,
        timestamp: expect.any(String),
        path: '/api/test',
      });
    });

    it('should handle unknown exception types', () => {
      // Arrange
      const exception = { message: 'Unknown error' };

      // Act
      filter.catch(exception as any, mockArgumentsHost as ArgumentsHost);

      // Assert
      expect(mockResponse.status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(mockResponse.json).toHaveBeenCalledWith({
        statusCode: HttpStatus.INTERNAL_SERVER_ERROR,
        code: 'INTERNAL_SERVER_ERROR',
        message: 'Internal server error',
        details: null,
        timestamp: expect.any(String),
        path: '/api/test',
      });
    });

    it('should include timestamp in response', () => {
      // Arrange
      const exception = new HttpException('Test', HttpStatus.BAD_REQUEST);
      const beforeTime = new Date().toISOString();

      // Act
      filter.catch(exception, mockArgumentsHost as ArgumentsHost);

      // Assert
      const callArgs = (mockResponse.json as jest.Mock).mock.calls[0][0];
      const afterTime = new Date().toISOString();
      expect(callArgs.timestamp).toBeDefined();
      expect(callArgs.timestamp >= beforeTime).toBe(true);
      expect(callArgs.timestamp <= afterTime).toBe(true);
    });
  });
});
