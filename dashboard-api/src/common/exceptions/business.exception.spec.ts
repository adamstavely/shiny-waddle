/**
 * Business Exception Unit Tests
 */

import { HttpStatus } from '@nestjs/common';
import {
  BusinessException,
  ValidationException,
  NotFoundException,
  ConflictException,
  UnauthorizedException,
  ForbiddenException,
  InternalServerException,
} from './business.exception';

describe('BusinessException', () => {
  describe('BusinessException', () => {
    it('should create exception with default status code', () => {
      // Act
      const exception = new BusinessException('Test message');

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.BAD_REQUEST);
      expect(exception.message).toBe('Test message');
    });

    it('should create exception with custom status code', () => {
      // Act
      const exception = new BusinessException('Test message', HttpStatus.NOT_FOUND);

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.NOT_FOUND);
    });

    it('should create exception with code', () => {
      // Act
      const exception = new BusinessException('Test message', HttpStatus.BAD_REQUEST, 'TEST_CODE');

      // Assert
      expect(exception.code).toBe('TEST_CODE');
    });

    it('should create exception with details', () => {
      // Act
      const exception = new BusinessException('Test message', HttpStatus.BAD_REQUEST, 'TEST_CODE', { field: 'value' });

      // Assert
      expect(exception.details).toEqual({ field: 'value' });
    });

    it('should include timestamp in response', () => {
      // Act
      const exception = new BusinessException('Test message');

      // Assert
      const response = exception.getResponse() as any;
      expect(response.timestamp).toBeDefined();
    });
  });

  describe('ValidationException', () => {
    it('should create validation exception', () => {
      // Act
      const exception = new ValidationException('Validation failed');

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.BAD_REQUEST);
      expect(exception.code).toBe('VALIDATION_ERROR');
      expect(exception.message).toBe('Validation failed');
    });

    it('should create validation exception with details', () => {
      // Act
      const exception = new ValidationException('Validation failed', { field: 'email' });

      // Assert
      expect(exception.details).toEqual({ field: 'email' });
    });
  });

  describe('NotFoundException', () => {
    it('should create not found exception without id', () => {
      // Act
      const exception = new NotFoundException('Resource');

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.NOT_FOUND);
      expect(exception.code).toBe('NOT_FOUND');
      expect(exception.message).toBe('Resource not found');
    });

    it('should create not found exception with id', () => {
      // Act
      const exception = new NotFoundException('Resource', 'resource-1');

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.NOT_FOUND);
      expect(exception.code).toBe('NOT_FOUND');
      expect(exception.message).toBe('Resource with id resource-1 not found');
      expect(exception.details).toEqual({ resource: 'Resource', id: 'resource-1' });
    });
  });

  describe('ConflictException', () => {
    it('should create conflict exception', () => {
      // Act
      const exception = new ConflictException('Resource already exists');

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.CONFLICT);
      expect(exception.code).toBe('CONFLICT');
      expect(exception.message).toBe('Resource already exists');
    });
  });

  describe('UnauthorizedException', () => {
    it('should create unauthorized exception with default message', () => {
      // Act
      const exception = new UnauthorizedException();

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.UNAUTHORIZED);
      expect(exception.code).toBe('UNAUTHORIZED');
      expect(exception.message).toBe('Unauthorized');
    });

    it('should create unauthorized exception with custom message', () => {
      // Act
      const exception = new UnauthorizedException('Custom message');

      // Assert
      expect(exception.message).toBe('Custom message');
    });
  });

  describe('ForbiddenException', () => {
    it('should create forbidden exception with default message', () => {
      // Act
      const exception = new ForbiddenException();

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.FORBIDDEN);
      expect(exception.code).toBe('FORBIDDEN');
      expect(exception.message).toBe('Forbidden');
    });

    it('should create forbidden exception with custom message', () => {
      // Act
      const exception = new ForbiddenException('Custom message');

      // Assert
      expect(exception.message).toBe('Custom message');
    });
  });

  describe('InternalServerException', () => {
    it('should create internal server exception with default message', () => {
      // Act
      const exception = new InternalServerException();

      // Assert
      expect(exception.getStatus()).toBe(HttpStatus.INTERNAL_SERVER_ERROR);
      expect(exception.code).toBe('INTERNAL_SERVER_ERROR');
      expect(exception.message).toBe('Internal server error');
    });

    it('should create internal server exception with custom message', () => {
      // Act
      const exception = new InternalServerException('Custom error');

      // Assert
      expect(exception.message).toBe('Custom error');
    });
  });
});
