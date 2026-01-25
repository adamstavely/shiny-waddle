import { Module } from '@nestjs/common';
import { DashboardSSEGateway } from './dashboard-sse.gateway';
import { DashboardSSEController } from './dashboard-sse.controller';

@Module({
  controllers: [DashboardSSEController],
  providers: [DashboardSSEGateway],
  exports: [DashboardSSEGateway],
})
export class DashboardModule {}

