import { Controller, Get, Query } from '@nestjs/common';
import { DashboardService } from './dashboard.service';

@Controller('api/v1')
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  @Get('dashboard-data')
  async getDashboardData() {
    return this.dashboardService.getDashboardData();
  }

  @Get('reports')
  async getReports() {
    return this.dashboardService.getReports();
  }

  @Get('analytics')
  async getAnalytics(@Query('timeRange') timeRange?: string) {
    const range = timeRange ? parseInt(timeRange, 10) : 30;
    return this.dashboardService.getAnalytics(range);
  }

  @Get('executive-metrics')
  async getExecutiveMetrics(@Query('timeRange') timeRange?: string) {
    const range = timeRange ? parseInt(timeRange, 10) : 30;
    return this.dashboardService.getExecutiveMetrics(range);
  }

  @Get('risk-metrics')
  async getRiskMetrics(@Query('timeRange') timeRange?: string) {
    const range = timeRange ? parseInt(timeRange, 10) : 30;
    return this.dashboardService.getRiskMetrics(range);
  }
}

