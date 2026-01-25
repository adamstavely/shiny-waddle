/**
 * Violations Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotFoundException } from '@nestjs/common';
import { ViolationsService } from './violations.service';
import { CreateViolationDto, ViolationStatus, ViolationSeverity, ViolationType } from './dto/create-violation.dto';
import { UpdateViolationDto } from './dto/update-violation.dto';
import { ViolationEntity } from './entities/violation.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('ViolationsService', () => {
  let service: ViolationsService;

  const mockViolation: ViolationEntity = {
    id: 'violation-1',
    title: 'Test Violation',
    description: 'Test violation description',
    type: ViolationType.ACCESS_CONTROL,
    severity: ViolationSeverity.HIGH,
    status: ViolationStatus.OPEN,
    application: 'app-1',
    team: 'platform-team',
    policyName: 'Test Policy',
    policyId: 'policy-1',
    resource: 'resource-1',
    affectedResources: [],
    testResultId: 'test-result-1',
    testResultDetails: {},
    remediationSuggestions: [],
    remediationStatus: undefined,
    remediationTimeline: [],
    verificationTestIds: [],
    comments: [],
    detectedAt: new Date(),
    assignedTo: 'user-1',
    relatedViolationIds: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [ViolationsService],
    }).compile();

    service = module.get<ViolationsService>(ViolationsService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue(JSON.stringify([]));
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear cached violations
    (service as any).violations = [];
  });

  describe('create', () => {
    const createDto: CreateViolationDto = {
      title: 'New Violation',
      description: 'New violation description',
      type: ViolationType.ACCESS_CONTROL,
      severity: ViolationSeverity.HIGH,
      status: ViolationStatus.OPEN,
      application: 'app-1',
      team: 'platform-team',
      policyName: 'Test Policy',
      policyId: 'policy-1',
      resource: 'resource-1',
    };

    it('should successfully create a violation', async () => {
      // Arrange
      (service as any).violations = [];

      // Act
      const result = await service.create(createDto);

      // Assert
      expect(result).toBeDefined();
      expect(result.title).toBe(createDto.title);
      expect(result.type).toBe(createDto.type);
      expect(result.severity).toBe(createDto.severity);
      expect(result.status).toBe(createDto.status);
      expect(result.remediationTimeline).toEqual([]);
      expect(result.comments).toEqual([]);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should use default status when not provided', async () => {
      // Arrange
      (service as any).violations = [];

      const createDtoWithoutStatus: CreateViolationDto = {
        ...createDto,
        status: undefined,
      };

      // Act
      const result = await service.create(createDtoWithoutStatus);

      // Assert
      expect(result.status).toBe(ViolationStatus.OPEN);
    });

    it('should initialize empty arrays for optional fields', async () => {
      // Arrange
      (service as any).violations = [];

      const createDtoMinimal: CreateViolationDto = {
        ...createDto,
        affectedResources: undefined,
        remediationSuggestions: undefined,
        relatedViolationIds: undefined,
      };

      // Act
      const result = await service.create(createDtoMinimal);

      // Assert
      expect(result.affectedResources).toEqual([]);
      expect(result.remediationSuggestions).toEqual([]);
      expect(result.relatedViolationIds).toEqual([]);
    });
  });

  describe('findAll', () => {
    it('should return all violations when no filters provided', async () => {
      // Arrange
      (service as any).violations = [mockViolation];

      // Act
      const result = await service.findAll();

      // Assert
      expect(result).toBeDefined();
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThanOrEqual(0);
    });

    it('should filter by severity', async () => {
      // Arrange
      const lowSeverityViolation = { ...mockViolation, id: 'violation-2', severity: ViolationSeverity.LOW };
      (service as any).violations = [mockViolation, lowSeverityViolation];

      // Act
      const result = await service.findAll('high');

      // Assert
      expect(result.every(v => v.severity === ViolationSeverity.HIGH)).toBe(true);
    });

    it('should filter by type', async () => {
      // Arrange
      const otherTypeViolation = { ...mockViolation, id: 'violation-2', type: ViolationType.DATASET_HEALTH };
      (service as any).violations = [mockViolation, otherTypeViolation];

      // Act
      const result = await service.findAll(undefined, 'access-control');

      // Assert
      expect(result.every(v => v.type === ViolationType.ACCESS_CONTROL)).toBe(true);
    });

    it('should filter by status', async () => {
      // Arrange
      const resolvedViolation = { ...mockViolation, id: 'violation-2', status: ViolationStatus.RESOLVED };
      (service as any).violations = [mockViolation, resolvedViolation];

      // Act
      const result = await service.findAll(undefined, undefined, ViolationStatus.OPEN);

      // Assert
      expect(result.every(v => v.status === ViolationStatus.OPEN)).toBe(true);
    });

    it('should filter by application', async () => {
      // Arrange
      const otherAppViolation = { ...mockViolation, id: 'violation-2', application: 'app-2' };
      (service as any).violations = [mockViolation, otherAppViolation];

      // Act
      const result = await service.findAll(undefined, undefined, undefined, 'app-1');

      // Assert
      expect(result.every(v => v.application === 'app-1')).toBe(true);
    });

    it('should filter by team', async () => {
      // Arrange
      const otherTeamViolation = { ...mockViolation, id: 'violation-2', team: 'other-team' };
      (service as any).violations = [mockViolation, otherTeamViolation];

      // Act
      const result = await service.findAll(undefined, undefined, undefined, undefined, 'platform-team');

      // Assert
      expect(result.every(v => v.team === 'platform-team')).toBe(true);
    });

    it('should apply multiple filters', async () => {
      // Arrange
      const otherViolation = {
        ...mockViolation,
        id: 'violation-2',
        severity: 'low',
        status: ViolationStatus.RESOLVED,
        application: 'app-2',
      };
      (service as any).violations = [mockViolation, otherViolation];

      // Act
      const result = await service.findAll('high', 'access-control', ViolationStatus.OPEN, 'app-1', 'platform-team');

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].severity).toBe(ViolationSeverity.HIGH);
      expect(result[0].status).toBe(ViolationStatus.OPEN);
      expect(result[0].application).toBe('app-1');
    });
  });

  describe('findOne', () => {
    it('should return violation when found', async () => {
      // Arrange
      (service as any).violations = [mockViolation];

      // Act
      const result = await service.findOne(mockViolation.id);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBe(mockViolation.id);
      expect(result.title).toBe(mockViolation.title);
    });

    it('should throw NotFoundException when violation not found', async () => {
      // Arrange
      (service as any).violations = [];

      // Act & Assert
      await expect(
        service.findOne('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('update', () => {
    const updateDto: UpdateViolationDto = {
      title: 'Updated Violation Title',
      description: 'Updated description',
    };

    it('should successfully update a violation', async () => {
      // Arrange
      (service as any).violations = [{ ...mockViolation }];

      // Act
      const result = await service.update(mockViolation.id, updateDto);

      // Assert
      expect(result.title).toBe(updateDto.title);
      expect(result.description).toBe(updateDto.description);
      expect(result.updatedAt).toBeInstanceOf(Date);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when violation not found', async () => {
      // Arrange
      (service as any).violations = [];

      // Act & Assert
      await expect(
        service.update('non-existent-id', updateDto)
      ).rejects.toThrow(NotFoundException);
    });

    it('should track status changes in remediation timeline', async () => {
      // Arrange
      (service as any).violations = [{ ...mockViolation }];

      const updateDtoWithStatus: UpdateViolationDto = {
        status: ViolationStatus.RESOLVED,
        resolvedBy: 'user-2',
      };

      // Act
      const result = await service.update(mockViolation.id, updateDtoWithStatus);

      // Assert
      expect(result.status).toBe(ViolationStatus.RESOLVED);
      expect(result.remediationTimeline.length).toBeGreaterThan(0);
      expect(result.remediationTimeline[0].type).toBe('status-change');
    });
  });

  describe('remove', () => {
    it('should successfully remove a violation', async () => {
      // Arrange
      (service as any).violations = [{ ...mockViolation }];

      // Act
      await service.remove(mockViolation.id);

      // Assert
      expect((service as any).violations.find((v: ViolationEntity) => v.id === mockViolation.id)).toBeUndefined();
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should throw NotFoundException when violation not found', async () => {
      // Arrange
      (service as any).violations = [];

      // Act & Assert
      await expect(
        service.remove('non-existent-id')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('addComment', () => {
    it('should successfully add a comment', async () => {
      // Arrange
      (service as any).violations = [{ ...mockViolation }];

      // Act
      const result = await service.addComment(mockViolation.id, 'user-1', 'Test comment');

      // Assert
      expect(result).toBeDefined();
      expect(result.author).toBe('user-1');
      expect(result.content).toBe('Test comment');
      expect(result.id).toBeDefined();
      expect(result.createdAt).toBeInstanceOf(Date);

      const violation = (service as any).violations.find((v: ViolationEntity) => v.id === mockViolation.id);
      expect(violation.comments.length).toBe(1);
      expect(violation.remediationTimeline.length).toBeGreaterThan(0);
    });

    it('should throw NotFoundException when violation not found', async () => {
      // Arrange
      (service as any).violations = [];

      // Act & Assert
      await expect(
        service.addComment('non-existent-id', 'user-1', 'Test comment')
      ).rejects.toThrow(NotFoundException);
    });

    it('should initialize comments array if it does not exist', async () => {
      // Arrange
      const violationWithoutComments = { ...mockViolation, comments: undefined };
      (service as any).violations = [violationWithoutComments];

      // Act
      await service.addComment(mockViolation.id, 'user-1', 'Test comment');

      // Assert
      const violation = (service as any).violations.find((v: ViolationEntity) => v.id === mockViolation.id);
      expect(violation.comments).toBeDefined();
      expect(Array.isArray(violation.comments)).toBe(true);
    });
  });

  describe('updateComment', () => {
    it('should successfully update a comment', async () => {
      // Arrange
      const violationWithComment = {
        ...mockViolation,
        comments: [{
          id: 'comment-1',
          author: 'user-1',
          content: 'Original comment',
          createdAt: new Date(),
        }],
      };
      (service as any).violations = [violationWithComment];

      // Act
      const result = await service.updateComment(mockViolation.id, 'comment-1', 'Updated comment');

      // Assert
      expect(result.content).toBe('Updated comment');
      expect(result.updatedAt).toBeInstanceOf(Date);
    });

    it('should throw NotFoundException when violation not found', async () => {
      // Arrange
      (service as any).violations = [];

      // Act & Assert
      await expect(
        service.updateComment('non-existent-id', 'comment-1', 'Updated')
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when comment not found', async () => {
      // Arrange
      (service as any).violations = [{ ...mockViolation }];

      // Act & Assert
      await expect(
        service.updateComment(mockViolation.id, 'non-existent-comment', 'Updated')
      ).rejects.toThrow(NotFoundException);
    });
  });

  describe('deleteComment', () => {
    it('should successfully delete a comment', async () => {
      // Arrange
      const violationWithComment = {
        ...mockViolation,
        comments: [{
          id: 'comment-1',
          author: 'user-1',
          content: 'Comment to delete',
          createdAt: new Date(),
        }],
      };
      (service as any).violations = [violationWithComment];

      // Act
      await service.deleteComment(mockViolation.id, 'comment-1');

      // Assert
      const violation = (service as any).violations.find((v: ViolationEntity) => v.id === mockViolation.id);
      expect(violation.comments.length).toBe(0);
    });

    it('should throw NotFoundException when violation not found', async () => {
      // Arrange
      (service as any).violations = [];

      // Act & Assert
      await expect(
        service.deleteComment('non-existent-id', 'comment-1')
      ).rejects.toThrow(NotFoundException);
    });

    it('should throw NotFoundException when comment not found', async () => {
      // Arrange
      (service as any).violations = [{ ...mockViolation }];

      // Act & Assert
      await expect(
        service.deleteComment(mockViolation.id, 'non-existent-comment')
      ).rejects.toThrow(NotFoundException);
    });
  });
});
