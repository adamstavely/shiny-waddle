/**
 * Sanitize Pipe Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { SanitizePipe } from './sanitize.pipe';
import { ArgumentMetadata } from '@nestjs/common';

describe('SanitizePipe', () => {
  let pipe: SanitizePipe;
  let metadata: ArgumentMetadata;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [SanitizePipe],
    }).compile();

    pipe = module.get<SanitizePipe>(SanitizePipe);

    metadata = {
      type: 'body',
      metatype: String,
      data: '',
    };
  });

  describe('transform', () => {
    it('should sanitize string values', () => {
      // Arrange
      const value = '<script>alert("xss")</script>';

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result).not.toContain('<script>');
      expect(result).not.toContain('</script>');
    });

    it('should sanitize object values', () => {
      // Arrange
      const value = {
        name: '<script>alert("xss")</script>',
        description: 'test--value;',
      };

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result.name).not.toContain('<script>');
      expect(result.description).not.toContain('--');
      expect(result.description).not.toContain(';');
    });

    it('should sanitize array values', () => {
      // Arrange
      const value = ['<script>tag1</script>', 'tag2--value'];

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result[0]).not.toContain('<script>');
      expect(result[1]).not.toContain('--');
    });

    it('should sanitize nested objects', () => {
      // Arrange
      const value = {
        user: {
          name: '<script>alert("xss")</script>',
          email: 'test@example.com',
        },
      };

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result.user.name).not.toContain('<script>');
    });

    it('should return primitives as-is', () => {
      // Arrange
      const numberValue = 123;
      const booleanValue = true;
      const nullValue = null;
      const undefinedValue = undefined;
      const emptyString = '';

      // Act
      const numberResult = pipe.transform(numberValue, metadata);
      const booleanResult = pipe.transform(booleanValue, metadata);
      const nullResult = pipe.transform(nullValue, metadata);
      const undefinedResult = pipe.transform(undefinedValue, metadata);
      const emptyStringResult = pipe.transform(emptyString, metadata);

      // Assert
      expect(numberResult).toBe(123);
      expect(booleanResult).toBe(true);
      expect(nullResult).toBeNull();
      expect(undefinedResult).toBeUndefined();
      expect(emptyStringResult).toBe('');
    });

    it('should remove SQL injection patterns', () => {
      // Arrange
      const value = {
        query: "SELECT * FROM users; DROP TABLE users--",
      };

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result.query).not.toContain(';');
      expect(result.query).not.toContain('--');
    });

    it('should remove null bytes', () => {
      // Arrange
      const value = {
        data: 'test\0value',
      };

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result.data).not.toContain('\0');
    });

    it('should trim whitespace', () => {
      // Arrange
      const value = {
        name: '  test value  ',
      };

      // Act
      const result = pipe.transform(value, metadata);

      // Assert
      expect(result.name).toBe('test value');
    });
  });
});
