import { Module } from '@nestjs/common';
import { RemediationTrackingController } from './remediation-tracking.controller';
import { RemediationTrackingService } from './remediation-tracking.service';
import { RemediationAutomationService } from './services/remediation-automation.service';
import { ViolationsModule } from '../violations/violations.module';

@Module({
  imports: [
    ViolationsModule,
  ],
  controllers: [RemediationTrackingController],
  providers: [RemediationTrackingService, RemediationAutomationService],
  exports: [RemediationTrackingService, RemediationAutomationService],
})
export class RemediationTrackingModule {}

