/**
 * SIEM Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException, BadRequestException } from '@nestjs/common';
import { SIEMService } from './siem.service';
import * as fs from 'fs/promises';
import * as path from 'path';

// Mock dependencies
jest.mock('fs/promises');

describe('SIEMService', () => {
  let service: SIEMService;

  const mockSIEMConfig = {
    type: 'splunk' as const,
    enabled: true,
    endpoint: 'https://splunk.example.com',
    authentication: {
      type: 'basic' as const,
      credentials: {
        username: 'admin',
        password: 'password',
      },
    },
  };

  beforeEach(async () => {
    (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT')); // File doesn't exist by default
    
    const module: TestingModule = await Test.createTestingModule({
      providers: [SIEMService],
    }).compile();

    service = module.get<SIEMService>(SIEMService);
    
    // Wait for async loadConfig to complete
    await new Promise(resolve => setImmediate(resolve));
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createIntegration', () => {
    it('should create SIEM integration', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (service as any).siemIntegration = {
        createAdapter: jest.fn(() => ({
          testConnection: jest.fn().mockResolvedValue(true),
        })),
        registerAdapter: jest.fn(),
      };

      // Act
      const result = await service.createIntegration(mockSIEMConfig);

      // Assert
      expect(result).toEqual(mockSIEMConfig);
    });

    it('should throw BadRequestException when connection fails', async () => {
      // Arrange
      (service as any).siemIntegration = {
        createAdapter: jest.fn(() => ({
          testConnection: jest.fn().mockResolvedValue(false),
        })),
      };

      // Act & Assert
      await expect(service.createIntegration(mockSIEMConfig)).rejects.toThrow(BadRequestException);
    });
  });

  describe('findAllIntegrations', () => {
    it('should return all integrations', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();

      // Act
      const result = await service.findAllIntegrations();

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(mockSIEMConfig);
    });

    it('should return empty array when no integrations', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act
      const result = await service.findAllIntegrations();

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('findOneIntegration', () => {
    it('should return integration by type', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();

      // Act
      const result = await service.findOneIntegration('splunk');

      // Assert
      expect(result).toEqual(mockSIEMConfig);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.findOneIntegration('qradar')).rejects.toThrow(NotFoundException);
    });
  });

  describe('updateIntegration', () => {
    it('should update existing integration', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadConfig();
      (service as any).siemIntegration = {
        createAdapter: jest.fn(() => ({})),
        registerAdapter: jest.fn(),
      };

      // Act
      const result = await service.updateIntegration('splunk', { enabled: false });

      // Assert
      expect(result.enabled).toBe(false);
      expect(result.type).toBe('splunk');
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.updateIntegration('qradar', { enabled: false })).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteIntegration', () => {
    it('should delete integration', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      await (service as any).loadConfig();

      // Act
      await service.deleteIntegration('splunk');

      // Assert
      await expect(service.findOneIntegration('splunk')).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.deleteIntegration('qradar')).rejects.toThrow(NotFoundException);
    });
  });

  describe('testConnection', () => {
    it('should test SIEM connection', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();
      (service as any).siemIntegration = {
        testSIEMConnection: jest.fn().mockResolvedValue(true),
      };

      // Act
      const result = await service.testConnection('splunk');

      // Assert
      expect(result).toBe(true);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.testConnection('splunk')).rejects.toThrow(NotFoundException);
    });
  });

  describe('sendFinding', () => {
    it('should send finding to SIEM', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();
      const mockFinding = { id: 'finding-1', title: 'Test Finding' };
      (service as any).siemIntegration = {
        sendFindingToAll: jest.fn().mockResolvedValue(new Map([['splunk', true]])),
      };

      // Act
      const result = await service.sendFinding('splunk', mockFinding as any);

      // Assert
      expect(result).toBe(true);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.sendFinding('splunk', {} as any)).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when integration not enabled', async () => {
      // Arrange
      const disabledConfig = { ...mockSIEMConfig, enabled: false };
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([disabledConfig]));
      await (service as any).loadConfig();

      // Act & Assert
      await expect(service.sendFinding('splunk', {} as any)).rejects.toThrow(NotFoundException);
    });
  });

  describe('queryEvents', () => {
    it('should query SIEM events', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();
      (service as any).siemIntegration = {
        querySIEM: jest.fn().mockResolvedValue([
          { id: 'event-1', timestamp: '2026-01-01', message: 'Test event' },
        ]),
      };

      // Act
      const result = await service.queryEvents('splunk', 'search query', '2026-01-01', '2026-01-02');

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('event-1');
    });

    it('should query without time range', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSIEMConfig]));
      await (service as any).loadConfig();
      (service as any).siemIntegration = {
        querySIEM: jest.fn().mockResolvedValue([]),
      };

      // Act
      const result = await service.queryEvents('splunk', 'search query');

      // Assert
      expect(result).toEqual([]);
    });

    it('should throw NotFoundException when integration not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT'));
      await (service as any).loadConfig().catch(() => {});

      // Act & Assert
      await expect(service.queryEvents('splunk', 'query')).rejects.toThrow(NotFoundException);
    });
  });
});
