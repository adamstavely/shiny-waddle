import { Module, forwardRef } from '@nestjs/common';
import { RemediationTrackingController } from './remediation-tracking.controller';
import { RemediationTrackingService } from './remediation-tracking.service';
import { RemediationAutomationService } from './services/remediation-automation.service';
import { ViolationsModule } from '../violations/violations.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
  imports: [
    forwardRef(() => ViolationsModule),
    forwardRef(() => NotificationsModule),
  ],
  controllers: [RemediationTrackingController],
  providers: [RemediationTrackingService, RemediationAutomationService],
  exports: [RemediationTrackingService, RemediationAutomationService],
})
export class RemediationTrackingModule {}

