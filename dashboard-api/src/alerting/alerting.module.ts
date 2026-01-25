import { Module } from '@nestjs/common';
import { AlertingController } from './alerting.controller';
import { AlertingService } from './alerting.service';

@Module({
  controllers: [AlertingController],
  providers: [AlertingService],
  exports: [AlertingService],
})
export class AlertingModule {}
