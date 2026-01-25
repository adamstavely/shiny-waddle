/**
 * Cloud Provider Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { CloudProviderService } from './cloud-provider.service';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock dependencies
jest.mock('fs/promises');

describe('CloudProviderService', () => {
  let service: CloudProviderService;

  const mockConfig = {
    provider: 'aws' as const,
    enabled: true,
    config: {
      credentials: {
        accessKeyId: 'test-key',
        secretAccessKey: 'test-secret',
      },
      regions: ['us-east-1'],
    },
  };

  beforeEach(async () => {
    (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT')); // File doesn't exist by default
    
    const module: TestingModule = await Test.createTestingModule({
      providers: [CloudProviderService],
    }).compile();

    service = module.get<CloudProviderService>(CloudProviderService);
    
    // Wait for async loadConfig to complete
    await new Promise(resolve => setImmediate(resolve));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createProvider', () => {
    it('should create a cloud provider', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      const result = await service.createProvider(mockConfig);

      // Assert
      expect(result).toEqual(mockConfig);
      expect(await service.findOneProvider('aws')).toEqual(mockConfig);
    });

    it('should save config to file', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);

      // Act
      await service.createProvider(mockConfig);

      // Assert
      expect(fs.writeFile).toHaveBeenCalled();
    });
  });

  describe('findAllProviders', () => {
    it('should return all providers', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      // Reload configs
      await (service as any).loadConfig();

      // Act
      const result = await service.findAllProviders();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(mockConfig);
    });

    it('should return empty array when no providers', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      // Reload configs
      await (service as any).loadConfig().catch(() => {}); // Ignore error

      // Act
      const result = await service.findAllProviders();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOneProvider', () => {
    it('should return provider by name', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      // Reload configs
      await (service as any).loadConfig();

      // Act
      const result = await service.findOneProvider('aws');

      // Assert
      expect(result).toEqual(mockConfig);
    });

    it('should throw NotFoundException when provider not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      // Reload configs
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.findOneProvider('azure')).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateProvider', () => {
    it('should update existing provider', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      // Reload configs
      await (service as any).loadConfig();

      // Act
      const result = await service.updateProvider('aws', { enabled: false });

      // Assert
      expect(result.enabled).toBe(false);
      expect(result.provider).toBe('aws');
    });

    it('should throw NotFoundException when provider not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      // Reload configs
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.updateProvider('azure', { enabled: false })).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteProvider', () => {
    it('should delete provider', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      // Reload configs
      await (service as any).loadConfig();

      // Act
      await service.deleteProvider('aws');

      // Assert
      await expect(service.findOneProvider('aws')).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when provider not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockConfig]));
      // Reload configs
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.deleteProvider('azure')).rejects.toThrow(NotFoundException);
    });
  });

  describe('normalizeFindings', () => {
    it('should normalize findings for provider', async () => {
      // Arrange
      const rawFindings = [{ id: 'finding-1', severity: 'high' }];
      (service as any).multiCloud = {
        normalizeProviderFindings: jest.fn().mockResolvedValue([{ id: 'finding-1', normalized: true }]),
      };

      // Act
      const result = await service.normalizeFindings('aws', rawFindings);

      // Assert
      expect(result).toEqual([{ id: 'finding-1', normalized: true }]);
    });
  });

  describe('aggregateFindings', () => {
    it('should aggregate findings from multiple providers', async () => {
      // Arrange
      const providerFindings = {
        aws: [{ id: 'finding-1' }],
        azure: [{ id: 'finding-2' }],
      };
      (service as any).multiCloud = {
        aggregateFindings: jest.fn().mockResolvedValue([
          { id: 'finding-1', provider: 'aws' },
          { id: 'finding-2', provider: 'azure' },
        ]),
      };

      // Act
      const result = await service.aggregateFindings(providerFindings);

      // Assert
      expect(result).toHaveLength(2);
    });
  });

  describe('getProviderSummaries', () => {
    it('should get provider summaries', async () => {
      // Arrange
      const findings = [{ id: 'finding-1', provider: 'aws' }];
      const summaries = new Map([['aws', { count: 1, severity: 'high' }]]);
      (service as any).multiCloud = {
        getProviderSummaries: jest.fn().mockResolvedValue(summaries),
      };

      // Act
      const result = await service.getProviderSummaries(findings as any);

      // Assert
      expect(result).toEqual(summaries);
    });
  });

  describe('findCrossCloudDuplicates', () => {
    it('should find cross-cloud duplicate findings', async () => {
      // Arrange
      const findings = [
        { id: 'finding-1', title: 'Same Finding' },
        { id: 'finding-2', title: 'Same Finding' },
      ];
      const duplicates = new Map([['Same Finding', findings]]);
      (service as any).multiCloud = {
        findCrossCloudDuplicates: jest.fn().mockReturnValue(duplicates),
      };

      // Act
      const result = await service.findCrossCloudDuplicates(findings as any);

      // Assert
      expect(result).toEqual(duplicates);
    });
  });
});
