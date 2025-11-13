import { Module } from '@nestjs/common';
import { UnifiedFindingsController } from './unified-findings.controller';
import { UnifiedFindingsService } from './unified-findings.service';
import { ApplicationsModule } from '../applications/applications.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [ApplicationsModule, NotificationsModule, UsersModule],
  controllers: [UnifiedFindingsController],
  providers: [UnifiedFindingsService],
  exports: [UnifiedFindingsService],
})
export class UnifiedFindingsModule {}

