/**
 * Remediation Automation Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { RemediationAutomationService } from './remediation-automation.service';
import { RemediationTrackingService } from '../remediation-tracking.service';
import { NotificationsService } from '../../notifications/notifications.service';
import { RemediationTracking } from '../entities/remediation-tracking.entity';
import { NotificationType } from '../../notifications/entities/notification.entity';

describe('RemediationAutomationService', () => {
  let service: RemediationAutomationService;
  let remediationService: jest.Mocked<RemediationTrackingService>;
  let notificationsService: jest.Mocked<NotificationsService>;

  const mockTracking: RemediationTracking = {
    id: 'tracking-1',
    violationId: 'violation-1',
    status: 'in-progress',
    progress: 50,
    milestones: [],
    effectiveness: 'unknown',
    isRecurrence: false,
    recurrenceCount: 0,
    recurrenceHistory: [],
    remediationSteps: [],
    assignedTo: 'user-1',
    targetDate: new Date(Date.now() + 5 * 24 * 60 * 60 * 1000), // 5 days from now
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(async () => {
    const mockRemediationService = {
      findAllTrackings: jest.fn().mockResolvedValue([]),
      updateTracking: jest.fn().mockResolvedValue(mockTracking),
    };

    const mockNotificationsService = {
      getUserPreferences: jest.fn().mockReturnValue({
        userId: 'user-1',
        enabled: true,
        scoreDropThreshold: 5,
        notifyOnCriticalFinding: true,
        notifyOnApprovalRequest: true,
        notifyOnApprovalStatusChanged: true,
        notifyOnRemediationDeadline: true,
        notifyOnRemediationOverdue: true,
        notifyOnMilestoneDeadline: true,
        notifyOnMilestoneOverdue: true,
      }),
      createNotification: jest.fn().mockResolvedValue({}),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        RemediationAutomationService,
        {
          provide: RemediationTrackingService,
          useValue: mockRemediationService,
        },
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
      ],
    }).compile();

    service = module.get<RemediationAutomationService>(RemediationAutomationService);
    remediationService = module.get(RemediationTrackingService) as jest.Mocked<RemediationTrackingService>;
    notificationsService = module.get(NotificationsService) as jest.Mocked<NotificationsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
    jest.useRealTimers();
  });

  describe('checkDeadlines', () => {
    it('should check deadlines and send reminders', async () => {
      // Arrange
      const trackingWithDeadline = {
        ...mockTracking,
        targetDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), // 3 days from now
      };
      remediationService.findAllTrackings.mockResolvedValue([trackingWithDeadline]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(remediationService.findAllTrackings).toHaveBeenCalled();
      expect(notificationsService.createNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: NotificationType.REMEDIATION_DEADLINE,
          userId: 'user-1',
        }),
      );
    });

    it('should escalate overdue remediations', async () => {
      // Arrange
      const overdueTracking = {
        ...mockTracking,
        status: 'in-progress' as const,
        targetDate: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
      };
      remediationService.findAllTrackings.mockResolvedValue([overdueTracking]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(remediationService.updateTracking).toHaveBeenCalledWith('tracking-1', {
        status: 'overdue',
      });
      expect(notificationsService.createNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: NotificationType.REMEDIATION_OVERDUE,
          userId: 'user-1',
        }),
      );
    });

    it('should skip completed and cancelled trackings', async () => {
      // Arrange
      const completedTracking = { ...mockTracking, status: 'completed' as const };
      const cancelledTracking = { ...mockTracking, id: 'tracking-2', status: 'cancelled' as const };
      remediationService.findAllTrackings.mockResolvedValue([completedTracking, cancelledTracking]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(notificationsService.createNotification).not.toHaveBeenCalled();
    });

    it('should check milestone deadlines', async () => {
      // Arrange
      const trackingWithMilestone = {
        ...mockTracking,
        milestones: [
          {
            id: 'milestone-1',
            name: 'Milestone 1',
            status: 'pending' as const,
            targetDate: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000), // 2 days from now
          },
        ],
      };
      remediationService.findAllTrackings.mockResolvedValue([trackingWithMilestone]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(notificationsService.createNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: NotificationType.MILESTONE_DEADLINE,
        }),
      );
    });

    it('should escalate overdue milestones', async () => {
      // Arrange
      const trackingWithOverdueMilestone = {
        ...mockTracking,
        milestones: [
          {
            id: 'milestone-1',
            name: 'Milestone 1',
            status: 'pending' as const,
            targetDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // 1 day ago
          },
        ],
      };
      remediationService.findAllTrackings.mockResolvedValue([trackingWithOverdueMilestone]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(notificationsService.createNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          type: NotificationType.MILESTONE_OVERDUE,
        }),
      );
    });

    it('should not send reminder when user preferences disabled', async () => {
      // Arrange
      notificationsService.getUserPreferences.mockReturnValue({
        userId: 'user-1',
        enabled: false,
        scoreDropThreshold: 5,
        notifyOnCriticalFinding: false,
        notifyOnApprovalRequest: false,
        notifyOnApprovalStatusChanged: false,
        notifyOnRemediationDeadline: false,
        notifyOnRemediationOverdue: false,
        notifyOnMilestoneDeadline: false,
        notifyOnMilestoneOverdue: false,
      });
      const trackingWithDeadline = {
        ...mockTracking,
        targetDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
      };
      remediationService.findAllTrackings.mockResolvedValue([trackingWithDeadline]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(notificationsService.createNotification).not.toHaveBeenCalled();
    });

    it('should not send reminder when tracking has no assigned user', async () => {
      // Arrange
      const trackingWithoutUser = {
        ...mockTracking,
        assignedTo: undefined,
        targetDate: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000),
      };
      remediationService.findAllTrackings.mockResolvedValue([trackingWithoutUser]);

      // Act
      await service.checkDeadlines();

      // Assert
      expect(notificationsService.createNotification).not.toHaveBeenCalled();
    });
  });

  describe('getMetrics', () => {
    it('should calculate remediation metrics', async () => {
      // Arrange
      const trackings: RemediationTracking[] = [
        {
          ...mockTracking,
          id: 'tracking-1',
          status: 'completed',
          startedAt: new Date(Date.now() - 10 * 60 * 60 * 1000), // 10 hours ago
          completedAt: new Date(Date.now() - 1 * 60 * 60 * 1000), // 1 hour ago
          createdAt: new Date(Date.now() - 12 * 60 * 60 * 1000), // 12 hours ago
        },
        {
          ...mockTracking,
          id: 'tracking-2',
          status: 'in-progress',
          startedAt: new Date(Date.now() - 5 * 60 * 60 * 1000), // 5 hours ago
          createdAt: new Date(Date.now() - 6 * 60 * 60 * 1000), // 6 hours ago
        },
        {
          ...mockTracking,
          id: 'tracking-3',
          status: 'overdue',
          targetDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000), // 1 day ago
        },
      ];
      remediationService.findAllTrackings.mockResolvedValue(trackings);

      // Act
      const result = await service.getMetrics();

      // Assert
      expect(result.totalRemediations).toBe(3);
      expect(result.byStatus.completed).toBe(1);
      expect(result.byStatus['in-progress']).toBe(1);
      expect(result.byStatus.overdue).toBe(1);
      expect(result.averageTimeToStart).toBeGreaterThan(0);
      expect(result.averageTimeToComplete).toBeGreaterThan(0);
      expect(result.overdueCount).toBe(1);
    });

    it('should filter by date range', async () => {
      // Arrange
      const oldTracking = {
        ...mockTracking,
        createdAt: new Date('2025-01-01'),
      };
      const newTracking = {
        ...mockTracking,
        id: 'tracking-2',
        createdAt: new Date('2026-01-01'),
      };
      remediationService.findAllTrackings.mockResolvedValue([oldTracking, newTracking]);

      // Act
      const result = await service.getMetrics({
        startDate: new Date('2026-01-01'),
        endDate: new Date('2026-12-31'),
      });

      // Assert
      expect(result.totalRemediations).toBe(1);
    });

    it('should calculate upcoming deadlines', async () => {
      // Arrange
      const trackingWithUpcomingDeadline = {
        ...mockTracking,
        targetDate: new Date(Date.now() + 10 * 24 * 60 * 60 * 1000), // 10 days from now
      };
      remediationService.findAllTrackings.mockResolvedValue([trackingWithUpcomingDeadline]);

      // Act
      const result = await service.getMetrics();

      // Assert
      expect(result.upcomingDeadlines).toHaveLength(1);
      expect(result.upcomingDeadlines[0].trackingId).toBe('tracking-1');
      expect(result.upcomingDeadlines[0].daysRemaining).toBeGreaterThan(0);
    });

    it('should calculate escalation count', async () => {
      // Arrange
      const overdueTracking = {
        ...mockTracking,
        status: 'overdue' as const,
        targetDate: new Date(Date.now() - 1 * 24 * 60 * 60 * 1000),
      };
      remediationService.findAllTrackings.mockResolvedValue([overdueTracking]);

      // Act
      const result = await service.getMetrics();

      // Assert
      expect(result.escalationCount).toBeGreaterThan(0);
    });

    it('should return zero averages when no trackings have started/completed', async () => {
      // Arrange
      const notStartedTracking = {
        ...mockTracking,
        status: 'not-started' as const,
      };
      remediationService.findAllTrackings.mockResolvedValue([notStartedTracking]);

      // Act
      const result = await service.getMetrics();

      // Assert
      expect(result.averageTimeToStart).toBe(0);
      expect(result.averageTimeToComplete).toBe(0);
    });
  });

  describe('onModuleDestroy', () => {
    it('should clear reminder interval on destroy', () => {
      // Arrange
      const clearIntervalSpy = jest.spyOn(global, 'clearInterval');
      (service as any).reminderInterval = 12345 as any;

      // Act
      service.onModuleDestroy();

      // Assert
      expect(clearIntervalSpy).toHaveBeenCalledWith(12345);
      clearIntervalSpy.mockRestore();
    });

    it('should not throw when interval is null', () => {
      // Arrange
      (service as any).reminderInterval = null;

      // Act & Assert
      expect(() => service.onModuleDestroy()).not.toThrow();
    });
  });
});
