/**
 * Violations Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus, NotFoundException } from '@nestjs/common';
import { ViolationsController } from './violations.controller';
import { ViolationsService } from './violations.service';
import { CreateViolationDto, ViolationSeverity, ViolationType, ViolationStatus } from './dto/create-violation.dto';
import { UpdateViolationDto } from './dto/update-violation.dto';
import { ViolationEntity, ViolationComment } from './entities/violation.entity';

describe('ViolationsController', () => {
  let controller: ViolationsController;
  let violationsService: jest.Mocked<ViolationsService>;

  const mockViolation: ViolationEntity = {
    id: 'violation-1',
    title: 'Test Violation',
    description: 'Test violation description',
    type: ViolationType.ACCESS_CONTROL,
    severity: ViolationSeverity.HIGH,
    status: ViolationStatus.OPEN,
    application: 'app-1',
    team: 'team-1',
    policyId: 'policy-1',
    policyName: 'Test Policy',
    detectedAt: new Date(),
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const mockViolations: ViolationEntity[] = [
    mockViolation,
    {
      ...mockViolation,
      id: 'violation-2',
      severity: ViolationSeverity.CRITICAL,
      status: ViolationStatus.RESOLVED,
    },
  ];

  const mockComment: ViolationComment = {
    id: 'comment-1',
    author: 'user-1',
    content: 'Test comment',
    createdAt: new Date(),
  };

  beforeEach(async () => {
    const mockViolationsService = {
      create: jest.fn(),
      findAll: jest.fn(),
      findOne: jest.fn(),
      update: jest.fn(),
      remove: jest.fn(),
      addComment: jest.fn(),
      updateComment: jest.fn(),
      deleteComment: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ViolationsController],
      providers: [
        {
          provide: ViolationsService,
          useValue: mockViolationsService,
        },
      ],
    }).compile();

    controller = module.get<ViolationsController>(ViolationsController);
    violationsService = module.get(ViolationsService) as jest.Mocked<ViolationsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('create', () => {
    const createViolationDto: CreateViolationDto = {
      title: 'New Violation',
      description: 'New violation description',
      type: ViolationType.API_SECURITY,
      severity: ViolationSeverity.MEDIUM,
      status: ViolationStatus.OPEN,
      application: 'app-1',
    };

    it('should create a violation successfully', async () => {
      // Arrange
      violationsService.create.mockResolvedValue(mockViolation);

      // Act
      const result = await controller.create(createViolationDto);

      // Assert
      expect(result).toEqual(mockViolation);
      expect(violationsService.create).toHaveBeenCalledTimes(1);
      expect(violationsService.create).toHaveBeenCalledWith(createViolationDto);
    });
  });

  describe('findAll', () => {
    it('should return all violations when no filters provided', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue(mockViolations);

      // Act
      const result = await controller.findAll();

      // Assert
      expect(result).toEqual(mockViolations);
      expect(violationsService.findAll).toHaveBeenCalledWith(undefined, undefined, undefined, undefined, undefined);
    });

    it('should filter violations by severity', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue([mockViolations[1]]);

      // Act
      const result = await controller.findAll('critical');

      // Assert
      expect(result).toEqual([mockViolations[1]]);
      expect(violationsService.findAll).toHaveBeenCalledWith('critical', undefined, undefined, undefined, undefined);
    });

    it('should filter violations by type', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue([mockViolation]);

      // Act
      const result = await controller.findAll(undefined, 'access-control');

      // Assert
      expect(result).toEqual([mockViolation]);
      expect(violationsService.findAll).toHaveBeenCalledWith(undefined, 'access-control', undefined, undefined, undefined);
    });

    it('should filter violations by status', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue([mockViolations[1]]);

      // Act
      const result = await controller.findAll(undefined, undefined, 'resolved');

      // Assert
      expect(result).toEqual([mockViolations[1]]);
      expect(violationsService.findAll).toHaveBeenCalledWith(undefined, undefined, 'resolved', undefined, undefined);
    });

    it('should filter violations by application', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue([mockViolation]);

      // Act
      const result = await controller.findAll(undefined, undefined, undefined, 'app-1');

      // Assert
      expect(result).toEqual([mockViolation]);
      expect(violationsService.findAll).toHaveBeenCalledWith(undefined, undefined, undefined, 'app-1', undefined);
    });

    it('should filter violations by team', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue([mockViolation]);

      // Act
      const result = await controller.findAll(undefined, undefined, undefined, undefined, 'team-1');

      // Assert
      expect(result).toEqual([mockViolation]);
      expect(violationsService.findAll).toHaveBeenCalledWith(undefined, undefined, undefined, undefined, 'team-1');
    });

    it('should filter violations by all parameters', async () => {
      // Arrange
      violationsService.findAll.mockResolvedValue([mockViolation]);

      // Act
      const result = await controller.findAll('high', 'access-control', 'open', 'app-1', 'team-1');

      // Assert
      expect(result).toEqual([mockViolation]);
      expect(violationsService.findAll).toHaveBeenCalledWith('high', 'access-control', 'open', 'app-1', 'team-1');
    });
  });

  describe('findOne', () => {
    it('should return a violation by id', async () => {
      // Arrange
      violationsService.findOne.mockResolvedValue(mockViolation);

      // Act
      const result = await controller.findOne('violation-1');

      // Assert
      expect(result).toEqual(mockViolation);
      expect(violationsService.findOne).toHaveBeenCalledTimes(1);
      expect(violationsService.findOne).toHaveBeenCalledWith('violation-1');
    });

    it('should propagate NotFoundException when violation not found', async () => {
      // Arrange
      violationsService.findOne.mockRejectedValue(new NotFoundException('Violation not found'));

      // Act & Assert
      await expect(controller.findOne('non-existent')).rejects.toThrow(NotFoundException);
      expect(violationsService.findOne).toHaveBeenCalledWith('non-existent');
    });
  });

  describe('update', () => {
    const updateViolationDto: UpdateViolationDto = {
      status: ViolationStatus.IN_PROGRESS,
      assignedTo: 'user-1',
    };

    it('should update a violation successfully', async () => {
      // Arrange
      const updatedViolation = { ...mockViolation, ...updateViolationDto };
      violationsService.update.mockResolvedValue(updatedViolation);

      // Act
      const result = await controller.update('violation-1', updateViolationDto);

      // Assert
      expect(result).toEqual(updatedViolation);
      expect(violationsService.update).toHaveBeenCalledTimes(1);
      expect(violationsService.update).toHaveBeenCalledWith('violation-1', updateViolationDto);
    });

    it('should propagate NotFoundException when violation not found', async () => {
      // Arrange
      violationsService.update.mockRejectedValue(new NotFoundException('Violation not found'));

      // Act & Assert
      await expect(controller.update('non-existent', updateViolationDto)).rejects.toThrow(NotFoundException);
    });
  });

  describe('remove', () => {
    it('should delete a violation successfully', async () => {
      // Arrange
      violationsService.remove.mockResolvedValue(undefined);

      // Act
      await controller.remove('violation-1');

      // Assert
      expect(violationsService.remove).toHaveBeenCalledTimes(1);
      expect(violationsService.remove).toHaveBeenCalledWith('violation-1');
    });

    it('should propagate NotFoundException when violation not found', async () => {
      // Arrange
      violationsService.remove.mockRejectedValue(new NotFoundException('Violation not found'));

      // Act & Assert
      await expect(controller.remove('non-existent')).rejects.toThrow(NotFoundException);
    });
  });

  describe('addComment', () => {
    it('should add a comment to a violation', async () => {
      // Arrange
      violationsService.addComment.mockResolvedValue(mockComment);

      // Act
      const result = await controller.addComment('violation-1', 'user-1', 'Test comment');

      // Assert
      expect(result).toEqual(mockComment);
      expect(violationsService.addComment).toHaveBeenCalledTimes(1);
      expect(violationsService.addComment).toHaveBeenCalledWith('violation-1', 'user-1', 'Test comment');
    });
  });

  describe('updateComment', () => {
    const updatedComment = {
      ...mockComment,
      content: 'Updated comment',
      updatedAt: new Date(),
    };

    it('should update a comment', async () => {
      // Arrange
      violationsService.updateComment.mockResolvedValue(updatedComment);

      // Act
      const result = await controller.updateComment('violation-1', 'comment-1', 'Updated comment');

      // Assert
      expect(result).toEqual(updatedComment);
      expect(violationsService.updateComment).toHaveBeenCalledTimes(1);
      expect(violationsService.updateComment).toHaveBeenCalledWith('violation-1', 'comment-1', 'Updated comment');
    });
  });

  describe('deleteComment', () => {
    it('should delete a comment', async () => {
      // Arrange
      violationsService.deleteComment.mockResolvedValue(undefined);

      // Act
      await controller.deleteComment('violation-1', 'comment-1');

      // Assert
      expect(violationsService.deleteComment).toHaveBeenCalledTimes(1);
      expect(violationsService.deleteComment).toHaveBeenCalledWith('violation-1', 'comment-1');
    });
  });
});
