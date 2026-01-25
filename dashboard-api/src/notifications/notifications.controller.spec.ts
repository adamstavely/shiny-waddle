/**
 * Notifications Controller Unit Tests
 */

import { Test, TestingModule } from '@nestjs/testing';
import { NotificationsController } from './notifications.controller';
import { NotificationsService } from './notifications.service';
import { NotificationPreferences } from './entities/notification.entity';

describe('NotificationsController', () => {
  let controller: NotificationsController;
  let notificationsService: jest.Mocked<NotificationsService>;

  const mockUser: any = {
    id: 'user-1',
    userId: 'user-1',
  };

  const mockNotifications = [
    {
      id: 'notif-1',
      userId: 'user-1',
      title: 'Test Notification',
      message: 'Test message',
      type: 'violation' as any,
      read: false,
      createdAt: new Date(),
    },
  ];

  const mockPreferences: NotificationPreferences = {
    userId: 'user-1',
    enabled: true,
    scoreDropThreshold: 5,
    notifyOnCriticalFinding: true,
    notifyOnApprovalRequest: true,
    notifyOnApprovalStatusChanged: true,
  };

  beforeEach(async () => {
    const mockNotificationsService = {
      getUserNotifications: jest.fn(),
      getUnreadCount: jest.fn(),
      getUserPreferences: jest.fn(),
      updatePreferences: jest.fn(),
      markAsRead: jest.fn(),
      markAllAsRead: jest.fn(),
      deleteNotification: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [NotificationsController],
      providers: [
        {
          provide: NotificationsService,
          useValue: mockNotificationsService,
        },
      ],
    }).compile();

    controller = module.get<NotificationsController>(NotificationsController);
    notificationsService = module.get(NotificationsService) as jest.Mocked<NotificationsService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('getUserNotifications', () => {
    it('should get all user notifications', async () => {
      // Arrange
      notificationsService.getUserNotifications.mockResolvedValue(mockNotifications);

      // Act
      const result = await controller.getUserNotifications(mockUser);

      // Assert
      expect(result).toEqual(mockNotifications);
      expect(notificationsService.getUserNotifications).toHaveBeenCalledWith('user-1', false);
    });

    it('should get unread notifications only when unreadOnly=true', async () => {
      // Arrange
      notificationsService.getUserNotifications.mockResolvedValue(mockNotifications);

      // Act
      const result = await controller.getUserNotifications(mockUser, 'true');

      // Assert
      expect(result).toEqual(mockNotifications);
      expect(notificationsService.getUserNotifications).toHaveBeenCalledWith('user-1', true);
    });
  });

  describe('getUnreadCount', () => {
    it('should get unread notification count', async () => {
      // Arrange
      notificationsService.getUnreadCount.mockReturnValue(5);

      // Act
      const result = await controller.getUnreadCount(mockUser);

      // Assert
      expect(result).toEqual({ count: 5 });
      expect(notificationsService.getUnreadCount).toHaveBeenCalledWith('user-1');
    });
  });

  describe('getPreferences', () => {
    it('should get user notification preferences', async () => {
      // Arrange
      notificationsService.getUserPreferences.mockReturnValue(mockPreferences);

      // Act
      const result = await controller.getPreferences(mockUser);

      // Assert
      expect(result).toEqual(mockPreferences);
      expect(notificationsService.getUserPreferences).toHaveBeenCalledWith('user-1');
    });
  });

  describe('updatePreferences', () => {
    it('should update user notification preferences', async () => {
      // Arrange
      const updates: Partial<NotificationPreferences> = {
        notifyOnCriticalFinding: false,
      };
      const updatedPreferences = { ...mockPreferences, notifyOnCriticalFinding: false };
      notificationsService.updatePreferences.mockResolvedValue(updatedPreferences);

      // Act
      const result = await controller.updatePreferences(mockUser, updates);

      // Assert
      expect(result).toEqual(updatedPreferences);
      expect(notificationsService.updatePreferences).toHaveBeenCalledWith('user-1', updates);
    });
  });

  describe('markAsRead', () => {
    it('should mark notification as read', async () => {
      // Arrange
      notificationsService.markAsRead.mockResolvedValue(undefined);

      // Act
      const result = await controller.markAsRead('notif-1', mockUser);

      // Assert
      expect(result).toEqual({ success: true });
      expect(notificationsService.markAsRead).toHaveBeenCalledWith('notif-1', 'user-1');
    });
  });

  describe('markAllAsRead', () => {
    it('should mark all notifications as read', async () => {
      // Arrange
      notificationsService.markAllAsRead.mockResolvedValue(undefined);

      // Act
      const result = await controller.markAllAsRead(mockUser);

      // Assert
      expect(result).toEqual({ success: true });
      expect(notificationsService.markAllAsRead).toHaveBeenCalledWith('user-1');
    });
  });

  describe('deleteNotification', () => {
    it('should delete notification', async () => {
      // Arrange
      notificationsService.deleteNotification.mockResolvedValue(undefined);

      // Act
      const result = await controller.deleteNotification('notif-1', mockUser);

      // Assert
      expect(result).toEqual({ success: true });
      expect(notificationsService.deleteNotification).toHaveBeenCalledWith('notif-1', 'user-1');
    });
  });
});
