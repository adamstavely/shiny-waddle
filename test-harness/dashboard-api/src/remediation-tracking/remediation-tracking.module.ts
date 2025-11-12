import { Module, forwardRef } from '@nestjs/common';
import { RemediationTrackingController } from './remediation-tracking.controller';
import { RemediationTrackingService } from './remediation-tracking.service';
import { ViolationsModule } from '../violations/violations.module';

@Module({
  imports: [forwardRef(() => ViolationsModule)],
  controllers: [RemediationTrackingController],
  providers: [RemediationTrackingService],
  exports: [RemediationTrackingService],
})
export class RemediationTrackingModule {}

