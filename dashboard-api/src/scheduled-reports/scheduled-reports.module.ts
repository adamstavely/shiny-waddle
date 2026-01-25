import { Module } from '@nestjs/common';
import { ScheduledReportsController } from './scheduled-reports.controller';
import { ScheduledReportsService } from './scheduled-reports.service';
import { SchedulerService } from './scheduler.service';

@Module({
  controllers: [ScheduledReportsController],
  providers: [ScheduledReportsService, SchedulerService],
  exports: [ScheduledReportsService],
})
export class ScheduledReportsModule {}

