import { Module } from '@nestjs/common';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { DashboardSSEGateway } from './dashboard-sse.gateway';
import { DashboardSSEController } from './dashboard-sse.controller';

@Module({
  controllers: [DashboardController, DashboardSSEController],
  providers: [DashboardService, DashboardSSEGateway],
  exports: [DashboardSSEGateway],
})
export class DashboardModule {}

