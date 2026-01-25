/**
 * Encryption Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { EncryptionService, EncryptedData } from './encryption.service';

describe('EncryptionService', () => {
  let service: EncryptionService;

  beforeEach(async () => {
    // Set a test encryption key
    process.env.ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    const module: TestingModule = await Test.createTestingModule({
      providers: [EncryptionService],
    }).compile();

    service = module.get<EncryptionService>(EncryptionService);
  });

  afterEach(() => {
    delete process.env.ENCRYPTION_KEY;
  });

  describe('encryptAtRest', () => {
    it('should successfully encrypt a string', () => {
      // Arrange
      const plaintext = 'sensitive data';

      // Act
      const result = service.encryptAtRest(plaintext);

      // Assert
      expect(result).toBeDefined();
      expect(result.encrypted).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(result.algorithm).toBe('aes-256-gcm');
      expect(result.tag).toBeDefined(); // GCM mode includes tag
    });

    it('should successfully encrypt a Buffer', () => {
      // Arrange
      const plaintext = Buffer.from('sensitive data', 'utf8');

      // Act
      const result = service.encryptAtRest(plaintext);

      // Assert
      expect(result).toBeDefined();
      expect(result.encrypted).toBeDefined();
      expect(result.iv).toBeDefined();
    });

    it('should produce different encrypted values for same input (due to random IV)', () => {
      // Arrange
      const plaintext = 'sensitive data';

      // Act
      const result1 = service.encryptAtRest(plaintext);
      const result2 = service.encryptAtRest(plaintext);

      // Assert
      expect(result1.encrypted).not.toBe(result2.encrypted);
      expect(result1.iv).not.toBe(result2.iv);
    });
  });

  describe('decryptAtRest', () => {
    it('should successfully decrypt encrypted data', () => {
      // Arrange
      const plaintext = 'sensitive data';
      const encrypted = service.encryptAtRest(plaintext);

      // Act
      const result = service.decryptAtRest(encrypted);

      // Assert
      expect(result).toBe(plaintext);
    });

    it('should throw error for invalid encrypted data', () => {
      // Arrange
      const invalidEncrypted: EncryptedData = {
        encrypted: 'invalid',
        iv: 'invalid',
        algorithm: 'aes-256-gcm',
      };

      // Act & Assert
      expect(() => service.decryptAtRest(invalidEncrypted)).toThrow();
    });

    it('should throw error when tag is missing for GCM mode', () => {
      // Arrange
      const plaintext = 'sensitive data';
      const encrypted = service.encryptAtRest(plaintext);
      const encryptedWithoutTag = { ...encrypted, tag: undefined };

      // Act & Assert
      expect(() => service.decryptAtRest(encryptedWithoutTag)).toThrow();
    });
  });

  describe('encryptInTransit / decryptInTransit', () => {
    it('should encrypt and decrypt data for transit', () => {
      // Arrange
      const plaintext = 'sensitive data';

      // Act
      const encryptedString = service.encryptInTransit(plaintext);
      const decrypted = service.decryptInTransit(encryptedString);

      // Assert
      expect(decrypted).toBe(plaintext);
      expect(typeof encryptedString).toBe('string');
      expect(encryptedString).toContain('encrypted');
    });
  });

  describe('hash', () => {
    it('should generate a hash with salt', () => {
      // Act
      const result = service.hash('password123');

      // Assert
      expect(result.hash).toBeDefined();
      expect(result.salt).toBeDefined();
      expect(result.hash).not.toBe('password123');
      expect(result.hash.length).toBeGreaterThan(0);
    });

    it('should use provided salt when given', () => {
      // Arrange
      const salt = 'test-salt';

      // Act
      const result = service.hash('password123', salt);

      // Assert
      expect(result.salt).toBe(salt);
    });

    it('should produce different hashes for same input with different salts', () => {
      // Act
      const result1 = service.hash('password123', 'salt1');
      const result2 = service.hash('password123', 'salt2');

      // Assert
      expect(result1.hash).not.toBe(result2.hash);
    });
  });

  describe('verifyHash', () => {
    it('should verify correct hash', () => {
      // Arrange
      const password = 'password123';
      const { hash, salt } = service.hash(password);

      // Act
      const result = service.verifyHash(password, hash, salt);

      // Assert
      expect(result).toBe(true);
    });

    it('should reject incorrect hash', () => {
      // Arrange
      const password = 'password123';
      const { hash, salt } = service.hash(password);

      // Act
      const result = service.verifyHash('wrong-password', hash, salt);

      // Assert
      expect(result).toBe(false);
    });

    it('should reject hash with wrong salt', () => {
      // Arrange
      const password = 'password123';
      const { hash } = service.hash(password, 'salt1');

      // Act
      const result = service.verifyHash(password, hash, 'salt2');

      // Assert
      expect(result).toBe(false);
    });
  });

  describe('generateSecureToken', () => {
    it('should generate a secure token', () => {
      // Act
      const token = service.generateSecureToken();

      // Assert
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.length).toBe(64); // 32 bytes = 64 hex chars
    });

    it('should generate tokens of specified length', () => {
      // Act
      const token = service.generateSecureToken(16);

      // Assert
      expect(token.length).toBe(32); // 16 bytes = 32 hex chars
    });

    it('should generate different tokens each time', () => {
      // Act
      const token1 = service.generateSecureToken();
      const token2 = service.generateSecureToken();

      // Assert
      expect(token1).not.toBe(token2);
    });
  });
});
