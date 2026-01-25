import { Injectable, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { RemediationTrackingService } from '../remediation-tracking.service';
import { RemediationTracking } from '../entities/remediation-tracking.entity';
import { NotificationsService } from '../../notifications/notifications.service';
import { NotificationType } from '../../notifications/entities/notification.entity';

export interface RemediationMetrics {
  totalRemediations: number;
  byStatus: {
    'not-started': number;
    'in-progress': number;
    'completed': number;
    'overdue': number;
  };
  averageTimeToStart: number; // hours
  averageTimeToComplete: number; // hours
  overdueCount: number;
  upcomingDeadlines: Array<{
    trackingId: string;
    violationId: string;
    deadline: Date;
    daysRemaining: number;
  }>;
  escalationCount: number;
}

@Injectable()
export class RemediationAutomationService {
  private readonly logger = new Logger(RemediationAutomationService.name);
  private reminderInterval: NodeJS.Timeout | null = null;

  constructor(
    private readonly remediationService: RemediationTrackingService,
    private readonly moduleRef: ModuleRef,
  ) {
    // Start automated reminder checking
    this.startReminderService();
  }

  /**
   * Start the automated reminder service
   */
  private startReminderService(): void {
    // Check for reminders every hour
    this.reminderInterval = setInterval(() => {
      this.checkDeadlines().catch(err => {
        this.logger.error('Error checking deadlines:', err);
      });
    }, 60 * 60 * 1000); // 1 hour

    // Also check immediately on startup
    this.checkDeadlines().catch(err => {
      this.logger.error('Error checking deadlines on startup:', err);
    });
  }

  /**
   * Check for upcoming and overdue deadlines
   */
  async checkDeadlines(): Promise<void> {
    const trackings = await this.remediationService.findAllTrackings();
    const now = new Date();

    for (const tracking of trackings) {
      if (tracking.status === 'completed' || tracking.status === 'cancelled') {
        continue;
      }

      // Check for deadline
      if (tracking.targetDate) {
        const deadline = new Date(tracking.targetDate);
        const daysUntilDeadline = (deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

        // Send reminder if deadline is approaching (7 days, 3 days, 1 day, overdue)
        if (daysUntilDeadline <= 7 && daysUntilDeadline > 0) {
          await this.sendDeadlineReminder(tracking, daysUntilDeadline);
        }

        // Escalate if overdue
        if (daysUntilDeadline < 0) {
          await this.escalateOverdue(tracking, Math.abs(daysUntilDeadline));
        }
      }

      // Check milestone deadlines
      if (tracking.milestones) {
        for (const milestone of tracking.milestones) {
          if (milestone.targetDate && milestone.status !== 'completed') {
            const milestoneDeadline = new Date(milestone.targetDate);
            const daysUntilMilestone = (milestoneDeadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);

            if (daysUntilMilestone <= 3 && daysUntilMilestone > 0) {
              await this.sendMilestoneReminder(tracking, milestone, daysUntilMilestone);
            }

            if (daysUntilMilestone < 0) {
              await this.escalateOverdueMilestone(tracking, milestone, Math.abs(daysUntilMilestone));
            }
          }
        }
      }
    }
  }

  /**
   * Send deadline reminder
   */
  private async sendDeadlineReminder(
    tracking: RemediationTracking,
    daysRemaining: number
  ): Promise<void> {
    if (!tracking.assignedTo) {
      return;
    }

    try {
      const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
      if (!notificationsService) {
        return;
      }
      const preferences = notificationsService.getUserPreferences(tracking.assignedTo);
      if (preferences.enabled && preferences.notifyOnRemediationDeadline) {
        await notificationsService.createNotification({
          userId: tracking.assignedTo,
          type: NotificationType.REMEDIATION_DEADLINE,
          title: `Remediation Deadline Approaching`,
          message: `Remediation for violation ${tracking.violationId} is due in ${Math.round(daysRemaining)} day(s)`,
          metadata: {
            trackingId: tracking.id,
            violationId: tracking.violationId,
            daysRemaining: Math.round(daysRemaining),
          },
        });
      }
    } catch (err) {
      this.logger.error(`Failed to send deadline reminder for tracking ${tracking.id}:`, err);
    }
  }

  /**
   * Escalate overdue remediation
   */
  private async escalateOverdue(
    tracking: RemediationTracking,
    daysOverdue: number
  ): Promise<void> {
    // Mark as overdue if not already
    if (tracking.status !== 'overdue') {
      await this.remediationService.updateTracking(tracking.id, {
        status: 'overdue',
      });
    }

    // Send escalation notification
    if (tracking.assignedTo) {
      try {
        const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
        if (!notificationsService) {
          return;
        }
        const preferences = notificationsService.getUserPreferences(tracking.assignedTo);
        if (preferences.enabled) {
          await notificationsService.createNotification({
            userId: tracking.assignedTo,
            type: NotificationType.REMEDIATION_OVERDUE,
            title: `Remediation Overdue`,
            message: `Remediation for violation ${tracking.violationId} is ${Math.round(daysOverdue)} day(s) overdue`,
            metadata: {
              trackingId: tracking.id,
              violationId: tracking.violationId,
              daysOverdue: Math.round(daysOverdue),
            },
          });
        }
      } catch (err) {
        this.logger.error(`Failed to send escalation for tracking ${tracking.id}:`, err);
      }
    }

    // NOTE: Manager escalation not yet implemented
    // Future implementation should check if manager escalation is configured
    // and send notification to the assigned manager
    this.logger.warn(
      `Remediation ${tracking.id} is ${Math.round(daysOverdue)} days overdue - escalation required`
    );
  }

  /**
   * Send milestone reminder
   */
  private async sendMilestoneReminder(
    tracking: RemediationTracking,
    milestone: any,
    daysRemaining: number
  ): Promise<void> {
    if (!tracking.assignedTo) {
      return;
    }

    try {
      const preferences = this.notificationsService.getUserPreferences(tracking.assignedTo);
      if (preferences.enabled) {
        await this.notificationsService.createNotification({
          userId: tracking.assignedTo,
          type: NotificationType.MILESTONE_DEADLINE,
          title: `Milestone Deadline Approaching`,
          message: `Milestone "${milestone.name}" is due in ${Math.round(daysRemaining)} day(s)`,
          metadata: {
            trackingId: tracking.id,
            milestoneId: milestone.id,
            daysRemaining: Math.round(daysRemaining),
          },
        });
      }
    } catch (err) {
      this.logger.error(`Failed to send milestone reminder:`, err);
    }
  }

  /**
   * Escalate overdue milestone
   */
  private async escalateOverdueMilestone(
    tracking: RemediationTracking,
    milestone: any,
    daysOverdue: number
  ): Promise<void> {
    if (tracking.assignedTo) {
      try {
        const notificationsService = this.moduleRef.get(NotificationsService, { strict: false });
        if (!notificationsService) {
          return;
        }
        const preferences = notificationsService.getUserPreferences(tracking.assignedTo);
        if (preferences.enabled) {
          await notificationsService.createNotification({
            userId: tracking.assignedTo,
            type: NotificationType.MILESTONE_OVERDUE,
            title: `Milestone Overdue`,
            message: `Milestone "${milestone.name}" is ${Math.round(daysOverdue)} day(s) overdue`,
            metadata: {
              trackingId: tracking.id,
              milestoneId: milestone.id,
              daysOverdue: Math.round(daysOverdue),
            },
          });
        }
      } catch (err) {
        this.logger.error(`Failed to send milestone escalation:`, err);
      }
    }
  }


  /**
   * Get remediation metrics dashboard
   */
  async getMetrics(options?: {
    applicationId?: string;
    teamName?: string;
    startDate?: Date;
    endDate?: Date;
  }): Promise<RemediationMetrics> {
    const trackings = await this.remediationService.findAllTrackings();
    
    // Filter trackings based on options
    let filtered = trackings;
    if (options?.startDate || options?.endDate) {
      filtered = filtered.filter(t => {
        const created = new Date(t.createdAt);
        if (options.startDate && created < options.startDate) return false;
        if (options.endDate && created > options.endDate) return false;
        return true;
      });
    }

    const now = new Date();
    const byStatus = {
      'not-started': 0,
      'in-progress': 0,
      'completed': 0,
      'overdue': 0,
    };

    let totalTimeToStart = 0;
    let totalTimeToComplete = 0;
    let startedCount = 0;
    let completedCount = 0;
    let overdueCount = 0;
    const upcomingDeadlines: RemediationMetrics['upcomingDeadlines'] = [];
    let escalationCount = 0;

    for (const tracking of filtered) {
      // Count by status
      if (tracking.status === 'overdue') {
        byStatus.overdue++;
        overdueCount++;
        escalationCount++;
      } else {
        byStatus[tracking.status as keyof typeof byStatus]++;
      }

      // Calculate time metrics
      if (tracking.startedAt) {
        const timeToStart = (tracking.startedAt.getTime() - new Date(tracking.createdAt).getTime()) / (1000 * 60 * 60);
        totalTimeToStart += timeToStart;
        startedCount++;
      }

      if (tracking.completedAt) {
        const timeToComplete = (tracking.completedAt.getTime() - new Date(tracking.createdAt).getTime()) / (1000 * 60 * 60);
        totalTimeToComplete += timeToComplete;
        completedCount++;
      }

      // Check upcoming deadlines
      if (tracking.targetDate && tracking.status !== 'completed') {
        const deadline = new Date(tracking.targetDate);
        const daysRemaining = (deadline.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
        
        if (daysRemaining > 0 && daysRemaining <= 30) {
          upcomingDeadlines.push({
            trackingId: tracking.id,
            violationId: tracking.violationId,
            deadline,
            daysRemaining: Math.round(daysRemaining),
          });
        }

        if (daysRemaining < 0) {
          escalationCount++;
        }
      }
    }

    return {
      totalRemediations: filtered.length,
      byStatus,
      averageTimeToStart: startedCount > 0 ? totalTimeToStart / startedCount : 0,
      averageTimeToComplete: completedCount > 0 ? totalTimeToComplete / completedCount : 0,
      overdueCount,
      upcomingDeadlines: upcomingDeadlines.sort((a, b) => a.daysRemaining - b.daysRemaining),
      escalationCount,
    };
  }

  /**
   * Cleanup on service destruction
   */
  onModuleDestroy(): void {
    if (this.reminderInterval) {
      clearInterval(this.reminderInterval);
    }
  }
}

