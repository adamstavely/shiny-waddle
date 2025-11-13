import { Module } from '@nestjs/common';
import { FindingApprovalsController } from './finding-approvals.controller';
import { FindingApprovalsService } from './finding-approvals.service';
import { UnifiedFindingsModule } from '../unified-findings/unified-findings.module';
import { UsersModule } from '../users/users.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
  imports: [UnifiedFindingsModule, NotificationsModule, UsersModule],
  controllers: [FindingApprovalsController],
  providers: [FindingApprovalsService],
})
export class FindingApprovalsModule {}

