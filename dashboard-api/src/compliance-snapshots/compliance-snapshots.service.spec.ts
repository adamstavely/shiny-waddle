/**
 * Compliance Snapshots Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ComplianceSnapshotsService } from './compliance-snapshots.service';
import { ApplicationsService } from '../applications/applications.service';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ComplianceSnapshotsService', () => {
  let service: ComplianceSnapshotsService;
  let applicationsService: jest.Mocked<ApplicationsService>;

  const mockApplication = {
    id: 'app-1',
    name: 'Test App',
    type: 'web' as const,
    status: 'active' as const,
    infrastructure: {},
    registeredAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockSnapshot = {
    id: 'snapshot-1',
    name: 'Snapshot 1',
    timestamp: new Date('2026-01-01'),
    applicationIds: ['app-1'],
    applications: [
      {
        id: 'app-1',
        name: 'Test App',
        score: 85,
      },
    ],
    overallScore: 85,
    createdAt: new Date('2026-01-01'),
  };

  beforeEach(async () => {
    const mockApplicationsService = {
      findAll: jest.fn().mockResolvedValue([mockApplication]),
      getComplianceScore: jest.fn().mockResolvedValue({ score: 85 }),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ComplianceSnapshotsService,
        {
          provide: ApplicationsService,
          useValue: mockApplicationsService,
        },
      ],
    }).compile();

    service = module.get<ComplianceSnapshotsService>(ComplianceSnapshotsService);
    applicationsService = module.get(ApplicationsService) as jest.Mocked<ApplicationsService>;
    (fs.readFile as jest.Mock).mockRejectedValue(new Error('ENOENT')); // File doesn't exist by default
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findAll', () => {
    it('should return all snapshots', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSnapshot]));

      // Act
      const result = await service.findAll({});

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('snapshot-1');
    });

    it('should filter by applicationId', async () => {
      // Arrange
      const snapshot2 = { ...mockSnapshot, id: 'snapshot-2', applicationIds: ['app-2'] };
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSnapshot, snapshot2]));

      // Act
      const result = await service.findAll({ applicationId: 'app-1' });

      // Assert
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('snapshot-1');
    });

    it('should limit results', async () => {
      // Arrange
      const snapshots = [mockSnapshot, { ...mockSnapshot, id: 'snapshot-2' }, { ...mockSnapshot, id: 'snapshot-3' }];
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify(snapshots));

      // Act
      const result = await service.findAll({ limit: 2 });

      // Assert
      expect(result).toHaveLength(2);
    });

    it('should sort by timestamp descending', async () => {
      // Arrange
      const snapshot1 = { ...mockSnapshot, id: 'snapshot-1', timestamp: new Date('2026-01-01') };
      const snapshot2 = { ...mockSnapshot, id: 'snapshot-2', timestamp: new Date('2026-01-02') };
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([snapshot1, snapshot2]));

      // Act
      const result = await service.findAll({});

      // Assert
      expect(result[0].id).toBe('snapshot-2'); // Most recent first
      expect(result[1].id).toBe('snapshot-1');
    });
  });

  describe('findOne', () => {
    it('should return snapshot by id', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSnapshot]));

      // Act
      const result = await service.findOne('snapshot-1');

      // Assert
      expect(result).toEqual(mockSnapshot);
    });

    it('should throw NotFoundException when snapshot not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSnapshot]));

      // Act & Assert
      await expect(service.findOne('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('create', () => {
    it('should create snapshot for all applications', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([]));

      // Act
      const result = await service.create({});

      // Assert
      expect(result.id).toBe('mock-uuid-v4');
      expect(result.applications).toHaveLength(1);
      expect(result.overallScore).toBe(85);
      expect(applicationsService.findAll).toHaveBeenCalled();
      expect(applicationsService.getComplianceScore).toHaveBeenCalledWith('app-1');
    });

    it('should create snapshot for specific applications', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([]));

      // Act
      const result = await service.create({ applicationIds: ['app-1'] });

      // Assert
      expect(result.applicationIds).toEqual(['app-1']);
      expect(result.applications).toHaveLength(1);
    });

    it('should handle applications without scores', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([]));
      applicationsService.getComplianceScore.mockRejectedValue(new Error('Score not available'));

      // Act
      const result = await service.create({});

      // Assert
      expect(result.applications[0].score).toBe(0);
      expect(result.overallScore).toBe(0);
    });

    it('should use custom name when provided', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([]));

      // Act
      const result = await service.create({ name: 'Custom Snapshot' });

      // Assert
      expect(result.name).toBe('Custom Snapshot');
    });

    it('should calculate overall score as average', async () => {
      // Arrange
      (fs.mkdir as jest.Mock).mockResolvedValue(undefined);
      (fs.writeFile as jest.Mock).mockResolvedValue(undefined);
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([]));
      const app2 = { ...mockApplication, id: 'app-2', name: 'App 2' };
      applicationsService.findAll.mockResolvedValue([mockApplication, app2] as any);
      applicationsService.getComplianceScore
        .mockResolvedValueOnce({ score: 80 })
        .mockResolvedValueOnce({ score: 90 });

      // Act
      const result = await service.create({});

      // Assert
      expect(result.overallScore).toBe(85); // (80 + 90) / 2 = 85
    });
  });

  describe('compare', () => {
    it('should compare two snapshots', async () => {
      // Arrange
      const snapshot1 = {
        ...mockSnapshot,
        id: 'snapshot-1',
        overallScore: 80,
        applications: [{ id: 'app-1', name: 'Test App', score: 80 }],
      };
      const snapshot2 = {
        ...mockSnapshot,
        id: 'snapshot-2',
        overallScore: 90,
        applications: [{ id: 'app-1', name: 'Test App', score: 90 }],
      };
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([snapshot1, snapshot2]));

      // Act
      const result = await service.compare('snapshot-1', 'snapshot-2');

      // Assert
      expect(result.snapshot1.id).toBe('snapshot-1');
      expect(result.snapshot2.id).toBe('snapshot-2');
      expect(result.overallChange).toBe(10); // 90 - 80
      expect(result.differences).toHaveLength(1);
      expect(result.differences[0].change).toBe(10);
    });

    it('should detect new applications in snapshot2', async () => {
      // Arrange
      const snapshot1 = {
        ...mockSnapshot,
        id: 'snapshot-1',
        applications: [{ id: 'app-1', name: 'App 1', score: 80 }],
      };
      const snapshot2 = {
        ...mockSnapshot,
        id: 'snapshot-2',
        applicationIds: ['app-1', 'app-2'],
        applications: [
          { id: 'app-1', name: 'App 1', score: 80 },
          { id: 'app-2', name: 'App 2', score: 90 },
        ],
      };
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([snapshot1, snapshot2]));

      // Act
      const result = await service.compare('snapshot-1', 'snapshot-2');

      // Assert
      expect(result.differences).toHaveLength(1);
      expect(result.differences[0].applicationId).toBe('app-2');
      expect(result.differences[0].change).toBe(90); // New app score
    });

    it('should detect removed applications in snapshot2', async () => {
      // Arrange
      const snapshot1 = {
        ...mockSnapshot,
        id: 'snapshot-1',
        applicationIds: ['app-1', 'app-2'],
        applications: [
          { id: 'app-1', name: 'App 1', score: 80 },
          { id: 'app-2', name: 'App 2', score: 90 },
        ],
      };
      const snapshot2 = {
        ...mockSnapshot,
        id: 'snapshot-2',
        applicationIds: ['app-1'],
        applications: [{ id: 'app-1', name: 'App 1', score: 80 }],
      };
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([snapshot1, snapshot2]));

      // Act
      const result = await service.compare('snapshot-1', 'snapshot-2');

      // Assert
      expect(result.differences).toHaveLength(1);
      expect(result.differences[0].applicationId).toBe('app-2');
      expect(result.differences[0].change).toBe(-90); // Removed app
    });

    it('should throw NotFoundException when snapshot1 not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSnapshot]));

      // Act & Assert
      await expect(service.compare('non-existent', 'snapshot-1')).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when snapshot2 not found', async () => {
      // Arrange
      (fs.readFile as jest.Mock).mockResolvedValue(JSON.stringify([mockSnapshot]));

      // Act & Assert
      await expect(service.compare('snapshot-1', 'non-existent')).rejects.toThrow(NotFoundException);
    });
  });
});
