import { Module } from '@nestjs/common';
import { TestResultsController } from './test-results.controller';
import { TestResultsService } from './test-results.service';
import { DashboardModule } from '../dashboard/dashboard.module';

@Module({
  imports: [DashboardModule],
  controllers: [TestResultsController],
  providers: [TestResultsService],
  exports: [TestResultsService],
})
export class TestResultsModule {}

