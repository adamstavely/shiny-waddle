/**
 * Remediation Tracking Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { HttpStatus } from '@nestjs/common';
import { RemediationTrackingController } from './remediation-tracking.controller';
import { RemediationTrackingService } from './remediation-tracking.service';
import { RemediationAutomationService } from './services/remediation-automation.service';
import {
  CreateRemediationTrackingDto,
  RemediationTracking,
} from './entities/remediation-tracking.entity';

describe('RemediationTrackingController', () => {
  let controller: RemediationTrackingController;
  let trackingService: jest.Mocked<RemediationTrackingService>;
  let automationService: jest.Mocked<RemediationAutomationService>;

  const mockTracking: RemediationTracking = {
    id: 'tracking-1',
    violationId: 'violation-1',
    status: 'in-progress' as const,
    progress: 50,
    milestones: [],
    effectiveness: 'unknown' as const,
    isRecurrence: false,
    recurrenceCount: 0,
    recurrenceHistory: [],
    remediationSteps: [],
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockTrackingService = {
      createTracking: jest.fn(),
      findAllTrackings: jest.fn(),
      findOneTracking: jest.fn(),
      findByViolationId: jest.fn(),
      startRemediation: jest.fn(),
      updateProgress: jest.fn(),
      completeRemediation: jest.fn(),
      verifyRemediation: jest.fn(),
      trackRecurrence: jest.fn(),
      getMetrics: jest.fn(),
      addMilestone: jest.fn(),
      updateMilestone: jest.fn(),
      addStep: jest.fn(),
      updateStep: jest.fn(),
    };

    const mockAutomationService = {
      getMetrics: jest.fn(),
      checkDeadlines: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [RemediationTrackingController],
      providers: [
        {
          provide: RemediationTrackingService,
          useValue: mockTrackingService,
        },
        {
          provide: RemediationAutomationService,
          useValue: mockAutomationService,
        },
      ],
    }).compile();

    controller = module.get<RemediationTrackingController>(RemediationTrackingController);
    trackingService = module.get(RemediationTrackingService) as jest.Mocked<RemediationTrackingService>;
    automationService = module.get(RemediationAutomationService) as jest.Mocked<RemediationAutomationService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createTracking', () => {
    const dto: CreateRemediationTrackingDto = {
      violationId: 'violation-1',
    };

    it('should create a tracking', async () => {
      // Arrange
      trackingService.createTracking.mockResolvedValue(mockTracking);

      // Act
      const result = await controller.createTracking(dto);

      // Assert
      expect(result).toEqual(mockTracking);
      expect(trackingService.createTracking).toHaveBeenCalledWith(dto);
    });
  });

  describe('findAllTrackings', () => {
    it('should find all trackings', async () => {
      // Arrange
      trackingService.findAllTrackings.mockResolvedValue([mockTracking]);

      // Act
      const result = await controller.findAllTrackings();

      // Assert
      expect(result).toEqual([mockTracking]);
      expect(trackingService.findAllTrackings).toHaveBeenCalledWith(undefined);
    });

    it('should find trackings filtered by violationId', async () => {
      // Arrange
      trackingService.findAllTrackings.mockResolvedValue([mockTracking]);

      // Act
      const result = await controller.findAllTrackings('violation-1');

      // Assert
      expect(result).toEqual([mockTracking]);
      expect(trackingService.findAllTrackings).toHaveBeenCalledWith('violation-1');
    });
  });

  describe('findOneTracking', () => {
    it('should find one tracking', async () => {
      // Arrange
      trackingService.findOneTracking.mockResolvedValue(mockTracking);

      // Act
      const result = await controller.findOneTracking('tracking-1');

      // Assert
      expect(result).toEqual(mockTracking);
      expect(trackingService.findOneTracking).toHaveBeenCalledWith('tracking-1');
    });
  });

  describe('findByViolationId', () => {
    it('should find tracking by violation id', async () => {
      // Arrange
      trackingService.findByViolationId.mockResolvedValue(mockTracking);

      // Act
      const result = await controller.findByViolationId('violation-1');

      // Assert
      expect(result).toEqual(mockTracking);
      expect(trackingService.findByViolationId).toHaveBeenCalledWith('violation-1');
    });
  });

  describe('startRemediation', () => {
    it('should start remediation', async () => {
      // Arrange
      const started = { ...mockTracking, status: 'in-progress' as const };
      trackingService.startRemediation.mockResolvedValue(started);

      // Act
      const result = await controller.startRemediation('tracking-1', { actor: 'user-1' });

      // Assert
      expect(result).toEqual(started);
      expect(trackingService.startRemediation).toHaveBeenCalledWith('tracking-1', 'user-1');
    });
  });

  describe('updateProgress', () => {
    it('should update progress', async () => {
      // Arrange
      const updated = { ...mockTracking, progress: 75 };
      trackingService.updateProgress.mockResolvedValue(updated);

      // Act
      const result = await controller.updateProgress('tracking-1', { progress: 75 });

      // Assert
      expect(result).toEqual(updated);
      expect(trackingService.updateProgress).toHaveBeenCalledWith('tracking-1', 75, undefined, undefined);
    });
  });

  describe('completeRemediation', () => {
    it('should complete remediation', async () => {
      // Arrange
      const completed = { ...mockTracking, status: 'completed' as const };
      trackingService.completeRemediation.mockResolvedValue(completed);

      // Act
      const result = await controller.completeRemediation('tracking-1', {
        actor: 'user-1',
        effectiveness: 'effective',
      });

      // Assert
      expect(result).toEqual(completed);
      expect(trackingService.completeRemediation).toHaveBeenCalledWith('tracking-1', 'user-1', 'effective', undefined);
    });
  });

  describe('verifyRemediation', () => {
    it('should verify remediation', async () => {
      // Arrange
      const verified = { ...mockTracking, status: 'completed' as const };
      trackingService.verifyRemediation.mockResolvedValue(verified);

      // Act
      const result = await controller.verifyRemediation('tracking-1', {
        verifiedBy: 'user-1',
        verificationTestId: 'test-1',
        effective: true,
      });

      // Assert
      expect(result).toEqual(verified);
      expect(trackingService.verifyRemediation).toHaveBeenCalledWith('tracking-1', 'user-1', 'test-1', true);
    });
  });

  describe('trackRecurrence', () => {
    it('should track recurrence', async () => {
      // Arrange
      trackingService.trackRecurrence.mockResolvedValue(undefined);

      // Act
      const result = await controller.trackRecurrence('violation-1');

      // Assert
      expect(result).toBeUndefined();
      expect(trackingService.trackRecurrence).toHaveBeenCalledWith('violation-1');
    });
  });

  describe('getMetrics', () => {
    it('should get metrics', async () => {
      // Arrange
      const metrics = [{ id: 'metric-1' }];
      trackingService.getMetrics.mockResolvedValue(metrics as any);

      // Act
      const result = await controller.getMetrics();

      // Assert
      expect(result).toEqual(metrics);
      expect(trackingService.getMetrics).toHaveBeenCalledWith(undefined);
    });
  });

  describe('addMilestone', () => {
    it('should add milestone', async () => {
      // Arrange
      const milestone = { id: 'milestone-1', name: 'Milestone 1', status: 'pending' as const };
      const updated = { ...mockTracking, milestones: [milestone as any] };
      trackingService.addMilestone.mockResolvedValue(updated);

      // Act
      const result = await controller.addMilestone('tracking-1', milestone);

      // Assert
      expect(result).toEqual(updated);
      expect(trackingService.addMilestone).toHaveBeenCalledWith('tracking-1', milestone);
    });
  });

  describe('updateMilestone', () => {
    it('should update milestone', async () => {
      // Arrange
      const updates = { status: 'completed' };
      const updated = { ...mockTracking };
      trackingService.updateMilestone.mockResolvedValue(updated);

      // Act
      const result = await controller.updateMilestone('tracking-1', 'milestone-1', updates);

      // Assert
      expect(result).toEqual(updated);
      expect(trackingService.updateMilestone).toHaveBeenCalledWith('tracking-1', 'milestone-1', updates);
    });
  });

  describe('addStep', () => {
    it('should add step', async () => {
      // Arrange
      const step = { id: 'step-1' };
      const updated = { ...mockTracking };
      trackingService.addStep.mockResolvedValue(updated);

      // Act
      const result = await controller.addStep('tracking-1', step);

      // Assert
      expect(result).toEqual(updated);
      expect(trackingService.addStep).toHaveBeenCalledWith('tracking-1', step);
    });
  });

  describe('updateStep', () => {
    it('should update step', async () => {
      // Arrange
      const updates = { status: 'completed' };
      const updated = { ...mockTracking };
      trackingService.updateStep.mockResolvedValue(updated);

      // Act
      const result = await controller.updateStep('tracking-1', 'step-1', updates);

      // Assert
      expect(result).toEqual(updated);
      expect(trackingService.updateStep).toHaveBeenCalledWith('tracking-1', 'step-1', updates);
    });
  });

  describe('getAutomationMetrics', () => {
    it('should get automation metrics', async () => {
      // Arrange
      const metrics = { total: 10 };
      automationService.getMetrics.mockResolvedValue(metrics as any);

      // Act
      const result = await controller.getAutomationMetrics();

      // Assert
      expect(result).toEqual(metrics);
      expect(automationService.getMetrics).toHaveBeenCalledWith({});
    });
  });

  describe('checkDeadlines', () => {
    it('should check deadlines', async () => {
      // Arrange
      automationService.checkDeadlines.mockResolvedValue(undefined);

      // Act
      const result = await controller.checkDeadlines();

      // Assert
      expect(result).toEqual({ message: 'Deadline check completed' });
      expect(automationService.checkDeadlines).toHaveBeenCalledTimes(1);
    });
  });
});
