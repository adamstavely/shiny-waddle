import { Injectable, Logger } from '@nestjs/common';
import { PoliciesService } from '../policies.service';
import { AutomationService } from './automation.service';

export interface PolicyChangeNotification {
  id: string;
  policyId: string;
  policyName: string;
  changeType: 'created' | 'modified' | 'deleted' | 'status-changed';
  changedBy: string;
  changedAt: Date;
  recipients: string[];
  sent: boolean;
  sentAt?: Date;
  message: string;
}

export interface NotificationPreferences {
  userId: string;
  policyCreated: boolean;
  policyModified: boolean;
  policyDeleted: boolean;
  policyStatusChanged: boolean;
  complianceThreshold: number; // Notify if compliance drops below this
  gapDetected: boolean;
}

@Injectable()
export class PolicyNotificationsService {
  private readonly logger = new Logger(PolicyNotificationsService.name);
  private readonly notifications: Map<string, PolicyChangeNotification> = new Map();
  private readonly preferences: Map<string, NotificationPreferences> = new Map();

  constructor(
    private readonly policiesService: PoliciesService,
    private readonly automationService: AutomationService,
  ) {}

  /**
   * Notify stakeholders of a policy change
   */
  async notifyPolicyChange(
    policyId: string,
    changeType: 'created' | 'modified' | 'deleted' | 'status-changed',
    changedBy: string,
    additionalRecipients?: string[],
  ): Promise<void> {
    try {
      const policy = await this.policiesService.findOne(policyId);
      if (!policy) {
        this.logger.warn(`Policy ${policyId} not found, skipping notification`);
        return;
      }

      // Get recipients
      const recipients = await this.getRecipientsForPolicyChange(policyId, changeType, additionalRecipients);

      if (recipients.length === 0) {
        this.logger.log(`No recipients for policy change notification ${policyId}`);
        return;
      }

      // Create notification
      const notification: PolicyChangeNotification = {
        id: `notif-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        policyId,
        policyName: policy.name,
        changeType,
        changedBy,
        changedAt: new Date(),
        recipients,
        sent: false,
        message: this.generateNotificationMessage(policy, changeType, changedBy),
      };

      // Send notifications
      await this.sendNotifications(notification);

      // Store notification
      this.notifications.set(notification.id, notification);
      this.logger.log(`Sent policy change notification to ${recipients.length} recipient(s)`);
    } catch (error) {
      this.logger.error(`Error sending policy change notification:`, error);
      // Don't throw - notifications shouldn't block policy operations
    }
  }

  /**
   * Get recipients for a policy change
   */
  private async getRecipientsForPolicyChange(
    policyId: string,
    changeType: string,
    additionalRecipients?: string[],
  ): Promise<string[]> {
    const recipients = new Set<string>();

    // Add explicit recipients
    if (additionalRecipients) {
      additionalRecipients.forEach(email => recipients.add(email));
    }

    // In production, this would:
    // 1. Get policy owners/stewards
    // 2. Get users with notification preferences enabled
    // 3. Get security team members
    // 4. Get compliance officers

    // For now, return explicit recipients or empty array
    return Array.from(recipients);
  }

  /**
   * Generate notification message
   */
  private generateNotificationMessage(
    policy: any,
    changeType: string,
    changedBy: string,
  ): string {
    const changeTypeText = {
      'created': 'created',
      'modified': 'modified',
      'deleted': 'deleted',
      'status-changed': 'status changed',
    }[changeType] || 'changed';

    return `Policy "${policy.name}" has been ${changeTypeText} by ${changedBy}.\n\n` +
           `Policy Type: ${policy.type.toUpperCase()}\n` +
           `Status: ${policy.status}\n` +
           `Version: ${policy.version}\n\n` +
           `Please review the changes to ensure compliance requirements are met.`;
  }

  /**
   * Send notifications (email, in-app, etc.)
   */
  private async sendNotifications(notification: PolicyChangeNotification): Promise<void> {
    // In production, this would:
    // 1. Send emails via email service
    // 2. Send in-app notifications
    // 3. Send Slack/Teams messages if configured
    // 4. Create tickets if configured

    this.logger.log(`Would send notification to: ${notification.recipients.join(', ')}`);
    this.logger.log(`Message: ${notification.message}`);

    // Mark as sent
    notification.sent = true;
    notification.sentAt = new Date();
  }

  /**
   * Get notification history
   */
  async getNotificationHistory(policyId?: string): Promise<PolicyChangeNotification[]> {
    const allNotifications = Array.from(this.notifications.values());
    
    if (policyId) {
      return allNotifications.filter(n => n.policyId === policyId);
    }

    return allNotifications.sort((a, b) => 
      b.changedAt.getTime() - a.changedAt.getTime()
    );
  }

  /**
   * Set notification preferences for a user
   */
  async setPreferences(userId: string, preferences: Partial<NotificationPreferences>): Promise<NotificationPreferences> {
    const existing = this.preferences.get(userId) || {
      userId,
      policyCreated: true,
      policyModified: true,
      policyDeleted: true,
      policyStatusChanged: true,
      complianceThreshold: 80,
      gapDetected: true,
    };

    const updated = { ...existing, ...preferences };
    this.preferences.set(userId, updated);

    return updated;
  }

  /**
   * Get notification preferences for a user
   */
  async getPreferences(userId: string): Promise<NotificationPreferences | null> {
    return this.preferences.get(userId) || null;
  }

  /**
   * Notify about compliance threshold breach
   */
  async notifyComplianceThreshold(complianceScore: number, threshold: number): Promise<void> {
    if (complianceScore >= threshold) {
      return; // No notification needed
    }

    // Get users who want compliance threshold notifications
    const recipients: string[] = [];
    for (const [userId, prefs] of this.preferences.entries()) {
      if (complianceScore < prefs.complianceThreshold) {
        // In production, get user email from user service
        recipients.push(`${userId}@example.com`);
      }
    }

    if (recipients.length > 0) {
      this.logger.log(`Compliance score ${complianceScore}% is below threshold ${threshold}%. Notifying ${recipients.length} users.`);
      // In production, send actual notifications
    }
  }

  /**
   * Notify about gap detection
   */
  async notifyGapDetected(gap: any, recipients?: string[]): Promise<void> {
    const message = `A compliance gap has been detected:\n\n` +
                   `Title: ${gap.title}\n` +
                   `Severity: ${gap.severity}\n` +
                   `Description: ${gap.description}\n\n` +
                   `Please review and take appropriate action.`;

    this.logger.log(`Gap detected: ${gap.title}. Would notify: ${recipients?.join(', ') || 'configured recipients'}`);
    // In production, send actual notifications
  }
}
