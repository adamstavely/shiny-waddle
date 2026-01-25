/**
 * Compliance Snapshots Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { ComplianceSnapshotsController } from './compliance-snapshots.controller';
import { ComplianceSnapshotsService } from './compliance-snapshots.service';

describe('ComplianceSnapshotsController', () => {
  let controller: ComplianceSnapshotsController;
  let complianceSnapshotsService: jest.Mocked<ComplianceSnapshotsService>;

  const mockSnapshot = {
    id: 'snapshot-1',
    name: 'Snapshot 1',
    applicationIds: ['app-1'],
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockComplianceSnapshotsService = {
      findAll: jest.fn(),
      create: jest.fn(),
      findOne: jest.fn(),
      compare: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ComplianceSnapshotsController],
      providers: [
        {
          provide: ComplianceSnapshotsService,
          useValue: mockComplianceSnapshotsService,
        },
      ],
    }).compile();

    controller = module.get<ComplianceSnapshotsController>(ComplianceSnapshotsController);
    complianceSnapshotsService = module.get(ComplianceSnapshotsService) as jest.Mocked<ComplianceSnapshotsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('findAll', () => {
    it('should find all snapshots', async () => {
      // Arrange
      complianceSnapshotsService.findAll.mockResolvedValue([mockSnapshot] as any);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual([mockSnapshot]);
      expect(complianceSnapshotsService.findAll).toHaveBeenCalledWith({});
    });

    it('should find snapshots with filters', async () => {
      // Arrange
      complianceSnapshotsService.findAll.mockResolvedValue([mockSnapshot] as any);

      // Act
      const result = await controller.findAll('app-1', '10');

      // Assert
      expect(result).toEqual([mockSnapshot]);
      expect(complianceSnapshotsService.findAll).toHaveBeenCalledWith({
        applicationId: 'app-1',
        limit: 10,
      });
    });
  });

  describe('create', () => {
    const dto = {
      name: 'Snapshot 1',
      applicationIds: ['app-1'],
    };

    it('should create a snapshot', async () => {
      // Arrange
      complianceSnapshotsService.create.mockResolvedValue(mockSnapshot as any);

      // Act
      const result = await controller.create(dto);

      // Assert
      expect(result).toEqual(mockSnapshot);
      expect(complianceSnapshotsService.create).toHaveBeenCalledWith(dto);
    });
  });

  describe('findOne', () => {
    it('should find one snapshot', async () => {
      // Arrange
      complianceSnapshotsService.findOne.mockResolvedValue(mockSnapshot as any);

      // Act
      const result = await controller.findOne('snapshot-1');

      // Assert
      expect(result).toEqual(mockSnapshot);
      expect(complianceSnapshotsService.findOne).toHaveBeenCalledWith('snapshot-1');
    });
  });

  describe('compare', () => {
    it('should compare two snapshots', async () => {
      // Arrange
      const comparison = { differences: [] };
      complianceSnapshotsService.compare.mockResolvedValue(comparison as any);

      // Act
      const result = await controller.compare('snapshot-1', 'snapshot-2');

      // Assert
      expect(result).toEqual(comparison);
      expect(complianceSnapshotsService.compare).toHaveBeenCalledWith('snapshot-1', 'snapshot-2');
    });
  });
});
