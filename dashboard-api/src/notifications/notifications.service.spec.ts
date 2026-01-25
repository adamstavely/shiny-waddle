/**
 * Notifications Service Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotificationsService } from './notifications.service';
import { Notification, NotificationType } from './entities/notification.entity';
import * as fs from 'fs/promises';

// Mock dependencies
jest.mock('fs/promises');
jest.mock('uuid', () => ({
  v4: jest.fn(() => 'mock-uuid-v4'),
}));

describe('NotificationsService', () => {
  let service: NotificationsService;

  const mockNotification: Omit<Notification, 'id' | 'createdAt' | 'read'> = {
    userId: 'user-1',
    type: NotificationType.SCORE_DROP,
    title: 'Test Notification',
    message: 'Test notification message',
    metadata: { applicationId: 'app-1' },
  };

  beforeEach(async () => {
    jest.clearAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [NotificationsService],
    }).compile();

    service = module.get<NotificationsService>(NotificationsService);

    // Mock fs operations
    const fs = require('fs/promises');
    fs.mkdir = jest.fn().mockResolvedValue(undefined);
    fs.readFile = jest.fn().mockResolvedValue('[]');
    fs.writeFile = jest.fn().mockResolvedValue(undefined);

    // Clear notifications and preferences
    (service as any).notifications = [];
    (service as any).preferences = new Map();
  });

  describe('createNotification', () => {
    it('should successfully create a notification', async () => {
      // Arrange
      (service as any).notifications = [];

      // Act
      const result = await service.createNotification(mockNotification);

      // Assert
      expect(result).toBeDefined();
      expect(result.id).toBeDefined();
      expect(result.userId).toBe(mockNotification.userId);
      expect(result.type).toBe(mockNotification.type);
      expect(result.title).toBe(mockNotification.title);
      expect(result.message).toBe(mockNotification.message);
      expect(result.read).toBe(false);
      expect(result.createdAt).toBeInstanceOf(Date);
    });

    it('should set read to false by default', async () => {
      // Arrange
      (service as any).notifications = [];

      // Act
      const result = await service.createNotification(mockNotification);

      // Assert
      expect(result.read).toBe(false);
    });
  });

  describe('getUserNotifications', () => {
    beforeEach(() => {
      (service as any).notifications = [
        {
          id: 'notif-1',
          userId: 'user-1',
          type: NotificationType.SCORE_DROP,
          title: 'Notification 1',
          message: 'Message 1',
          read: false,
          createdAt: new Date('2024-01-01'),
        },
        {
          id: 'notif-2',
          userId: 'user-1',
          type: NotificationType.CRITICAL_FINDING,
          title: 'Notification 2',
          message: 'Message 2',
          read: true,
          createdAt: new Date('2024-01-02'),
        },
        {
          id: 'notif-3',
          userId: 'user-2',
          type: NotificationType.SCORE_DROP,
          title: 'Notification 3',
          message: 'Message 3',
          read: false,
          createdAt: new Date('2024-01-03'),
        },
      ];
    });

    it('should return all notifications for a user', async () => {
      // Act
      const result = await service.getUserNotifications('user-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result.every(n => n.userId === 'user-1')).toBe(true);
    });

    it('should return only unread notifications when unreadOnly is true', async () => {
      // Act
      const result = await service.getUserNotifications('user-1', true);

      // Assert
      expect(result.length).toBe(1);
      expect(result[0].read).toBe(false);
    });

    it('should return notifications sorted by date (newest first)', async () => {
      // Act
      const result = await service.getUserNotifications('user-1');

      // Assert
      expect(result.length).toBe(2);
      expect(result[0].createdAt.getTime()).toBeGreaterThan(result[1].createdAt.getTime());
    });

    it('should return empty array for user with no notifications', async () => {
      // Act
      const result = await service.getUserNotifications('user-3');

      // Assert
      expect(result).toEqual([]);
    });
  });

  describe('markAsRead', () => {
    beforeEach(() => {
      (service as any).notifications = [
        {
          id: 'notif-1',
          userId: 'user-1',
          type: NotificationType.SCORE_DROP,
          title: 'Notification 1',
          message: 'Message 1',
          read: false,
          createdAt: new Date(),
        },
      ];
    });

    it('should mark notification as read', async () => {
      // Act
      await service.markAsRead('notif-1', 'user-1');

      // Assert
      const notification = (service as any).notifications.find((n: Notification) => n.id === 'notif-1');
      expect(notification.read).toBe(true);
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should not mark notification as read if userId does not match', async () => {
      // Act
      await service.markAsRead('notif-1', 'user-2');

      // Assert
      const notification = (service as any).notifications.find((n: Notification) => n.id === 'notif-1');
      expect(notification.read).toBe(false);
    });
  });

  describe('getUserPreferences', () => {
    it('should return default preferences when user has no preferences', () => {
      // Act
      const result = service.getUserPreferences('user-1');

      // Assert
      expect(result.userId).toBe('user-1');
      expect(result.enabled).toBe(true);
      expect(result.scoreDropThreshold).toBe(5);
      expect(result.notifyOnCriticalFinding).toBe(true);
      expect(result.notifyOnApprovalRequest).toBe(true);
      expect(result.notifyOnApprovalStatusChanged).toBe(true);
    });

    it('should return user preferences when they exist', () => {
      // Arrange
      (service as any).preferences.set('user-1', {
        userId: 'user-1',
        enabled: false,
        scoreDropThreshold: 10,
        notifyOnCriticalFinding: false,
        notifyOnApprovalRequest: true,
        notifyOnApprovalStatusChanged: false,
      });

      // Act
      const result = service.getUserPreferences('user-1');

      // Assert
      expect(result.enabled).toBe(false);
      expect(result.scoreDropThreshold).toBe(10);
      expect(result.notifyOnCriticalFinding).toBe(false);
    });
  });

  describe('updatePreferences', () => {
    it('should update user preferences', async () => {
      // Arrange
      (service as any).preferences.set('user-1', {
        userId: 'user-1',
        enabled: true,
        scoreDropThreshold: 5,
        notifyOnCriticalFinding: true,
        notifyOnApprovalRequest: true,
        notifyOnApprovalStatusChanged: true,
      });

      // Act
      const result = await service.updatePreferences('user-1', {
        enabled: false,
        scoreDropThreshold: 10,
      });

      // Assert
      expect(result.enabled).toBe(false);
      expect(result.scoreDropThreshold).toBe(10);
      expect(result.notifyOnCriticalFinding).toBe(true); // Should preserve existing
      const fs = require('fs/promises');
      expect(fs.writeFile).toHaveBeenCalled();
    });

    it('should create preferences if they do not exist', async () => {
      // Act
      const result = await service.updatePreferences('user-1', {
        enabled: false,
      });

      // Assert
      expect(result.userId).toBe('user-1');
      expect(result.enabled).toBe(false);
      expect((service as any).preferences.has('user-1')).toBe(true);
    });
  });
});
