/**
 * Remediation Tracking Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { RemediationTrackingService } from './remediation-tracking.service';
import { ViolationsService } from '../violations/violations.service';
import { RemediationTracking, CreateRemediationTrackingDto } from './entities/remediation-tracking.entity';
import { ViolationEntity } from '../violations/entities/violation.entity';
import { ViolationType, ViolationSeverity, ViolationStatus } from '../violations/dto/create-violation.dto';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('RemediationTrackingService', () => {
  let service: RemediationTrackingService;
  let violationsService: jest.Mocked<ViolationsService>;

  const mockViolation: ViolationEntity = {
    id: 'violation-1',
    title: 'Test Violation',
    description: 'Test violation description',
    type: ViolationType.ACCESS_CONTROL,
    severity: ViolationSeverity.HIGH,
    application: 'app-1',
    team: 'team-1',
    status: ViolationStatus.OPEN,
    detectedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const createDto: CreateRemediationTrackingDto = {
    violationId: 'violation-1',
    assignedTo: 'user-1',
    remediationMethod: 'manual',
    milestones: [
      {
        name: 'Milestone 1',
        description: 'First milestone',
        status: 'pending',
        targetDate: new Date('2024-12-31'),
      },
    ],
    remediationSteps: [
      {
        description: 'First step',
        order: 1,
        status: 'pending',
      },
    ],
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const mockViolationsService = {
      findOne: jest.fn().mockResolvedValue(mockViolation),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RemediationTrackingService,
        {
          provide: ViolationsService,
          useValue: mockViolationsService,
        },
      ],
    }).compile();

    service = module.get<RemediationTrackingService>(RemediationTrackingService);
    violationsService = module.get(ViolationsService) as jest.Mocked<ViolationsService>;

    // Mock fs operations
    const fs = require('fs/promises');
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear trackings
    (service as any).trackings = [];
    
    // Mock checkRecurrence and isSameViolation
    jest.spyOn(service as any, 'checkRecurrence').mockResolvedValue(false);
    jest.spyOn(service as any, 'isSameViolation').mockReturnValue(false);
  });

  describe('createTracking', () => {
    it('should successfully create remediation tracking', async () => {
      // Arrange
      (service as any).trackings = [];

      // Act
      const result = await service.createTracking(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.violationId).toBe(createDto.violationId);
      expect(result.status).toBe('not-started');
      expect(result.progress).toBe(0);
      expect(result.milestones.length).toBe(1);
      expect(result.remediationSteps.length).toBe(1);
      expect(result.assignedTo).toBe(createDto.assignedTo);
      expect(result.remediationMethod).toBe('manual');
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw error when tracking already exists for violation', async () => {
      // Arrange
      (service as any).trackings = [
        { violationId: 'violation-1', id: 'tracking-1' },
      ];

      // Act & Assert
      await expect(
        service.createTracking(createDto)
      ).rejects.toThrow('Remediation tracking already exists');
    });

    it('should set default remediation method when not provided', async () => {
      // Arrange
      (service as any).trackings = [];
      const dtoWithoutMethod = { ...createDto, remediationMethod: undefined };

      // Act
      const result = await service.createTracking(dtoWithoutMethod);

      // Assert
      expect(result.remediationMethod).toBe('manual');
    });
  });

  describe('findAllTrackings', () => {
    beforeEach(() => {
      (service as any).trackings = [
        { id: 'tracking-1', violationId: 'violation-1' },
        { id: 'tracking-2', violationId: 'violation-2' },
        { id: 'tracking-3', violationId: 'violation-1' },
      ];
    });

    it('should return all trackings when no filter provided', async () => {
      // Act
      const result = await service.findAllTrackings();

      // Assert
      expect(result.length).toBe(3);
    });

    it('should filter by violationId when provided', async () => {
      // Act
      const result = await service.findAllTrackings('violation-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(t => t.violationId === 'violation-1')).toBe(true);
    });
  });

  describe('findOneTracking', () => {
    beforeEach(() => {
      (service as any).trackings = [
        { id: 'tracking-1', violationId: 'violation-1' },
      ];
    });

    it('should return tracking when found', async () => {
      // Act
      const result = await service.findOneTracking('tracking-1');

      // Assert
      expect(result.id).toBe('tracking-1');
    });

    it('should throw NotFoundException when tracking not found', async () => {
      // Act & Assert
      await expect(
        service.findOneTracking('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('findByViolationId', () => {
    beforeEach(() => {
      (service as any).trackings = [
        { id: 'tracking-1', violationId: 'violation-1' },
      ];
    });

    it('should return tracking when found', async () => {
      // Act
      const result = await service.findByViolationId('violation-1');

      // Assert
      expect(result).toBeDefined();
      expect(result?.id).toBe('tracking-1');
    });

    it('should return null when tracking not found', async () => {
      // Act
      const result = await service.findByViolationId('non-existent-violation');

      // Assert
      expect(result).toBeNull();
    });
  });

  describe('startRemediation', () => {
    beforeEach(() => {
      (service as any).trackings = [
        {
          id: 'tracking-1',
          violationId: 'violation-1',
          status: 'not-started',
        },
      ];
    });

    it('should start remediation and update status', async () => {
      // Act
      const result = await service.startRemediation('tracking-1', 'user-1');

      // Assert
      expect(result.status).toBe('in-progress');
      expect(result.startedAt).toBeInstanceOf(Date);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should calculate time to start when violation has detectedAt', async () => {
      // Arrange
      const detectedAt = new Date('2024-01-01');
      violationsService.findOne.mockResolvedValue({
        ...mockViolation,
        detectedAt,
      });

      // Act
      const result = await service.startRemediation('tracking-1', 'user-1');

      // Assert
      expect(result.timeToStart).toBeDefined();
      expect(typeof result.timeToStart).toBe('number');
    });
  });

  describe('updateTracking', () => {
    beforeEach(() => {
      (service as any).trackings = [
        {
          id: 'tracking-1',
          violationId: 'violation-1',
          status: 'not-started',
          progress: 0,
        },
      ];
    });

    it('should update tracking fields', async () => {
      // Act
      const result = await service.updateTracking('tracking-1', {
        status: 'in-progress',
        progress: 50,
      });

      // Assert
      expect(result.status).toBe('in-progress');
      expect(result.progress).toBe(50);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });
  });

  describe('updateProgress', () => {
    beforeEach(() => {
      (service as any).trackings = [
        {
          id: 'tracking-1',
          violationId: 'violation-1',
          progress: 0,
        },
      ];
    });

    it('should update progress', async () => {
      // Act
      const result = await service.updateProgress('tracking-1', 75);

      // Assert
      expect(result.progress).toBe(75);
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should clamp progress to 0-100 range', async () => {
      // Act
      const result = await service.updateProgress('tracking-1', 150);

      // Assert
      expect(result.progress).toBe(100);
    });
  });
});
