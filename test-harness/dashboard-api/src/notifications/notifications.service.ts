import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { Notification, NotificationType, NotificationPreferences } from './entities/notification.entity';

@Injectable()
export class NotificationsService {
  private readonly notificationsFile = path.join(process.cwd(), '..', '..', 'data', 'notifications.json');
  private readonly preferencesFile = path.join(process.cwd(), '..', '..', 'data', 'notification-preferences.json');
  private notifications: Notification[] = [];
  private preferences: Map<string, NotificationPreferences> = new Map();

  constructor() {
    this.loadData().catch(err => {
      console.error('Error loading notifications data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      // Load notifications
      try {
        await fs.mkdir(path.dirname(this.notificationsFile), { recursive: true });
        const notificationsData = await fs.readFile(this.notificationsFile, 'utf-8');
        if (notificationsData && notificationsData.trim()) {
          this.notifications = JSON.parse(notificationsData).map((n: any) => ({
            ...n,
            createdAt: new Date(n.createdAt),
          }));
        }
      } catch {
        this.notifications = [];
      }

      // Load preferences
      try {
        await fs.mkdir(path.dirname(this.preferencesFile), { recursive: true });
        const preferencesData = await fs.readFile(this.preferencesFile, 'utf-8');
        if (preferencesData && preferencesData.trim()) {
          const prefsArray = JSON.parse(preferencesData);
          prefsArray.forEach((pref: NotificationPreferences) => {
            this.preferences.set(pref.userId, pref);
          });
        }
      } catch {
        // Use defaults
      }
    } catch (error) {
      console.error('Error loading notifications data:', error);
    }
  }

  private async saveNotifications(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.notificationsFile), { recursive: true });
      await fs.writeFile(
        this.notificationsFile,
        JSON.stringify(this.notifications, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('Error saving notifications:', error);
      throw error;
    }
  }

  private async savePreferences(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.preferencesFile), { recursive: true });
      const prefsArray = Array.from(this.preferences.values());
      await fs.writeFile(
        this.preferencesFile,
        JSON.stringify(prefsArray, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('Error saving preferences:', error);
      throw error;
    }
  }

  /**
   * Get user preferences (with defaults)
   */
  getUserPreferences(userId: string): NotificationPreferences {
    if (this.preferences.has(userId)) {
      return this.preferences.get(userId)!;
    }

    // Return defaults
    return {
      userId,
      enabled: true,
      scoreDropThreshold: 5,
      notifyOnCriticalFinding: true,
      notifyOnApprovalRequest: true,
      notifyOnApprovalStatusChanged: true,
    };
  }

  /**
   * Update user preferences
   */
  async updatePreferences(userId: string, updates: Partial<NotificationPreferences>): Promise<NotificationPreferences> {
    const current = this.getUserPreferences(userId);
    const updated = { ...current, ...updates };
    this.preferences.set(userId, updated);
    await this.savePreferences();
    return updated;
  }

  /**
   * Create a notification
   */
  async createNotification(notification: Omit<Notification, 'id' | 'createdAt' | 'read'>): Promise<Notification> {
    const newNotification: Notification = {
      ...notification,
      id: uuidv4(),
      createdAt: new Date(),
      read: false,
    };

    this.notifications.push(newNotification);
    await this.saveNotifications();

    return newNotification;
  }

  /**
   * Get notifications for a user
   */
  async getUserNotifications(userId: string, unreadOnly: boolean = false): Promise<Notification[]> {
    let filtered = this.notifications.filter(n => n.userId === userId);

    if (unreadOnly) {
      filtered = filtered.filter(n => !n.read);
    }

    return filtered.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  /**
   * Mark notification as read
   */
  async markAsRead(notificationId: string, userId: string): Promise<void> {
    const notification = this.notifications.find(n => n.id === notificationId && n.userId === userId);
    if (notification) {
      notification.read = true;
      await this.saveNotifications();
    }
  }

  /**
   * Mark all notifications as read for a user
   */
  async markAllAsRead(userId: string): Promise<void> {
    this.notifications
      .filter(n => n.userId === userId && !n.read)
      .forEach(n => {
        n.read = true;
      });
    await this.saveNotifications();
  }

  /**
   * Delete a notification
   */
  async deleteNotification(notificationId: string, userId: string): Promise<void> {
    const index = this.notifications.findIndex(n => n.id === notificationId && n.userId === userId);
    if (index >= 0) {
      this.notifications.splice(index, 1);
      await this.saveNotifications();
    }
  }

  /**
   * Get unread count for a user
   */
  getUnreadCount(userId: string): number {
    return this.notifications.filter(n => n.userId === userId && !n.read).length;
  }

  /**
   * Notify about score drop
   */
  async notifyScoreDrop(
    userId: string,
    scoreChange: number,
    previousScore: number,
    currentScore: number,
    applicationId?: string,
    teamName?: string
  ): Promise<Notification | null> {
    const preferences = this.getUserPreferences(userId);
    
    if (!preferences.enabled) {
      return null;
    }

    // Check if drop exceeds threshold
    if (Math.abs(scoreChange) < preferences.scoreDropThreshold) {
      return null;
    }

    return this.createNotification({
      userId,
      type: NotificationType.SCORE_DROP,
      title: 'Compliance Score Dropped',
      message: `Your compliance score dropped by ${Math.abs(scoreChange)} points (from ${previousScore} to ${currentScore})`,
      metadata: {
        scoreChange,
        previousScore,
        currentScore,
        applicationId,
        teamName,
      },
    });
  }

  /**
   * Notify about critical finding
   */
  async notifyCriticalFinding(
    userId: string,
    findingId: string,
    findingTitle: string
  ): Promise<Notification | null> {
    const preferences = this.getUserPreferences(userId);
    
    if (!preferences.enabled || !preferences.notifyOnCriticalFinding) {
      return null;
    }

    return this.createNotification({
      userId,
      type: NotificationType.CRITICAL_FINDING,
      title: 'New Critical Finding',
      message: `A new critical finding was detected: ${findingTitle}`,
      metadata: {
        findingId,
      },
    });
  }

  /**
   * Notify about approval request
   */
  async notifyApprovalRequest(
    userId: string,
    approvalRequestId: string,
    findingId: string,
    findingTitle: string,
    requestType: 'risk-acceptance' | 'false-positive'
  ): Promise<Notification | null> {
    const preferences = this.getUserPreferences(userId);
    
    if (!preferences.enabled || !preferences.notifyOnApprovalRequest) {
      return null;
    }

    return this.createNotification({
      userId,
      type: NotificationType.APPROVAL_REQUEST,
      title: `Approval Request: ${requestType === 'risk-acceptance' ? 'Risk Acceptance' : 'False Positive'}`,
      message: `A ${requestType === 'risk-acceptance' ? 'risk acceptance' : 'false positive'} request was created for: ${findingTitle}`,
      metadata: {
        approvalRequestId,
        findingId,
      },
    });
  }

  /**
   * Notify about approval status change
   */
  async notifyApprovalStatusChanged(
    userId: string,
    approvalRequestId: string,
    findingId: string,
    findingTitle: string,
    status: 'approved' | 'rejected'
  ): Promise<Notification | null> {
    const preferences = this.getUserPreferences(userId);
    
    if (!preferences.enabled || !preferences.notifyOnApprovalStatusChanged) {
      return null;
    }

    return this.createNotification({
      userId,
      type: NotificationType.APPROVAL_STATUS_CHANGED,
      title: `Approval Request ${status === 'approved' ? 'Approved' : 'Rejected'}`,
      message: `Your approval request for "${findingTitle}" was ${status}`,
      metadata: {
        approvalRequestId,
        findingId,
      },
    });
  }
}

