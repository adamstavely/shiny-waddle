import { Controller, Get, Post, Patch, Delete, Param, Body, Query } from '@nestjs/common';
import { NotificationsService } from './notifications.service';
import { NotificationPreferences } from './entities/notification.entity';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { UserContext } from '../common/interfaces/user-context.interface';

@Controller('api/v1/notifications')
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  async getUserNotifications(
    @CurrentUser() user: UserContext,
    @Query('unreadOnly') unreadOnly?: string,
  ) {
    const unread = unreadOnly === 'true';
    return this.notificationsService.getUserNotifications(user.id, unread);
  }

  @Get('unread-count')
  async getUnreadCount(@CurrentUser() user: UserContext) {
    return { count: this.notificationsService.getUnreadCount(user.id) };
  }

  @Get('preferences')
  async getPreferences(@CurrentUser() user: UserContext) {
    return this.notificationsService.getUserPreferences(user.id);
  }

  @Patch('preferences')
  async updatePreferences(
    @CurrentUser() user: UserContext,
    @Body() updates: Partial<NotificationPreferences>,
  ) {
    return this.notificationsService.updatePreferences(user.id, updates);
  }

  @Patch(':id/read')
  async markAsRead(
    @Param('id') id: string,
    @CurrentUser() user: UserContext,
  ) {
    await this.notificationsService.markAsRead(id, user.id);
    return { success: true };
  }

  @Patch('read-all')
  async markAllAsRead(@CurrentUser() user: UserContext) {
    await this.notificationsService.markAllAsRead(user.id);
    return { success: true };
  }

  @Delete(':id')
  async deleteNotification(
    @Param('id') id: string,
    @CurrentUser() user: UserContext,
  ) {
    await this.notificationsService.deleteNotification(id, user.id);
    return { success: true };
  }
}

