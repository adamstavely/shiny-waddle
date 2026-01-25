import { Module, forwardRef } from '@nestjs/common';
import { ScheduledReportsController } from './scheduled-reports.controller';
import { ScheduledReportsService } from './scheduled-reports.service';
import { SchedulerService } from './scheduler.service';
import { ReportsModule } from '../reports/reports.module';

@Module({
  imports: [forwardRef(() => ReportsModule)],
  controllers: [ScheduledReportsController],
  providers: [ScheduledReportsService, SchedulerService],
  exports: [ScheduledReportsService],
})
export class ScheduledReportsModule {}

