/**
 * Secrets Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { SecretsService, Secret, CreateSecretDto, UpdateSecretDto } from './secrets.service';
import { EncryptionService } from './encryption.service';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('SecretsService', () => {
  let service: SecretsService;
  let encryptionService: jest.Mocked<EncryptionService>;

  const mockEncryptedData = {
    encrypted: 'encrypted-value',
    iv: 'iv-value',
    tag: 'tag-value',
    algorithm: 'aes-256-gcm',
  };

  const createDto: CreateSecretDto = {
    key: 'test-secret-key',
    value: 'secret-value',
    description: 'Test secret',
    tags: ['test', 'demo'],
    createdBy: 'user-1',
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    process.env.ENCRYPTION_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    const mockEncryptionService = {
      encryptAtRest: jest.fn().mockReturnValue(mockEncryptedData),
      decryptAtRest: jest.fn().mockReturnValue('secret-value'),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        SecretsService,
        {
          provide: EncryptionService,
          useValue: mockEncryptionService,
        },
      ],
    }).compile();

    service = module.get<SecretsService>(SecretsService);
    encryptionService = module.get(EncryptionService) as jest.Mocked<EncryptionService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.readFile = jest.fn().mockRejectedValue({ code: 'ENOENT' });
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.writeFile = jest.fn().mockResolvedValue(undefined);
    fs.rename = jest.fn().mockResolvedValue(undefined);
    fs.chmod = jest.fn().mockResolvedValue(undefined);

    // Clear secrets
    (service as any).secrets = new Map();
  });

  afterEach(() => {
    delete process.env.ENCRYPTION_KEY;
  });

  describe('createSecret', () => {
    it('should successfully create a secret', async () => {
      // Arrange
      (service as any).secrets = new Map();

      // Act
      const result = await service.createSecret(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.key).toBe(createDto.key);
      expect(result.description).toBe(createDto.description);
      expect(result.tags).toEqual(createDto.tags);
      expect(result.createdBy).toBe(createDto.createdBy);
      expect(result.value).toBe(JSON.stringify(mockEncryptedData));
      expect(result.createdAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
      expect(encryptionService.encryptAtRest).toHaveBeenCalledWith(createDto.value);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw error for duplicate key', async () => {
      // Arrange
      (service as any).secrets.set('secret-1', {
        id: 'secret-1',
        key: 'test-secret-key',
        value: 'encrypted',
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      // Act & Assert
      await expect(
        service.createSecret(createDto)
      ).rejects.toThrow('Secret with key "test-secret-key" already exists');
    });
  });

  describe('getSecretById', () => {
    beforeEach(() => {
      (service as any).secrets.set('secret-1', {
        id: 'secret-1',
        key: 'test-key',
        value: JSON.stringify(mockEncryptedData),
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });

    it('should return secret when found', async () => {
      // Act
      const result = await service.getSecretById('secret-1');

      // Assert
      expect(result.id).toBe('secret-1');
      expect(result.key).toBe('test-key');
    });

    it('should throw NotFoundException when secret not found', async () => {
      // Act & Assert
      await expect(
        service.getSecretById('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('getSecretByKey', () => {
    beforeEach(() => {
      (service as any).secrets.set('secret-1', {
        id: 'secret-1',
        key: 'test-key',
        value: JSON.stringify(mockEncryptedData),
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });

    it('should return decrypted secret when found', async () => {
      // Act
      const result = await service.getSecretByKey('test-key');

      // Assert
      expect(result.key).toBe('test-key');
      expect(result.value).toBe('secret-value'); // Decrypted value
      expect(encryptionService.decryptAtRest).toHaveBeenCalled();
    });

    it('should throw NotFoundException when secret not found', async () => {
      // Act & Assert
      await expect(
        service.getSecretByKey('non-existent-key')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateSecret', () => {
    beforeEach(() => {
      (service as any).secrets.set('secret-1', {
        id: 'secret-1',
        key: 'test-key',
        value: JSON.stringify(mockEncryptedData),
        description: 'Old description',
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });

    it('should successfully update a secret', async () => {
      // Arrange
      const updateDto: UpdateSecretDto = {
        value: 'new-secret-value',
        description: 'New description',
        updatedBy: 'user-2',
      };
      encryptionService.encryptAtRest.mockReturnValue({
        ...mockEncryptedData,
        encrypted: 'new-encrypted-value',
      });

      // Act
      const result = await service.updateSecret('secret-1', updateDto);

      // Assert
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedBy).toBe(updateDto.updatedBy);
      expect(result.updatedAt).toBeInstanceOf(Date);
      if (updateDto.value) {
        expect(encryptionService.encryptAtRest).toHaveBeenCalledWith(updateDto.value);
      }
    });

    it('should throw NotFoundException when secret not found', async () => {
      // Act & Assert
      await expect(
        service.updateSecret('non-existent-id', { description: 'Updated' })
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteSecret', () => {
    beforeEach(() => {
      (service as any).secrets.set('secret-1', {
        id: 'secret-1',
        key: 'test-key',
        value: JSON.stringify(mockEncryptedData),
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });

    it('should successfully delete a secret', async () => {
      // Act
      await service.deleteSecret('secret-1');

      // Assert
      expect((service as any).secrets.has('secret-1')).toBe(false);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when secret not found', async () => {
      // Act & Assert
      await expect(
        service.deleteSecret('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('listSecrets', () => {
    beforeEach(() => {
      (service as any).secrets.set('secret-1', {
        id: 'secret-1',
        key: 'key-1',
        value: JSON.stringify(mockEncryptedData),
        tags: ['tag1'],
        createdAt: new Date(),
        updatedAt: new Date(),
      });
      (service as any).secrets.set('secret-2', {
        id: 'secret-2',
        key: 'key-2',
        value: JSON.stringify(mockEncryptedData),
        tags: ['tag2'],
        createdAt: new Date(),
        updatedAt: new Date(),
      });
    });

    it('should return all secrets', async () => {
      // Act
      const result = await service.listSecrets();

      // Assert
      expect(result.length).toBe(2);
    });

    it('should filter by tags when provided', async () => {
      // Act
      const result = await service.listSecrets(['tag1']);

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].tags).toContain('tag1');
    });
  });
});
