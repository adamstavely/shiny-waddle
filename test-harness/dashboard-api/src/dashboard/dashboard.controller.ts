import { Controller, Get } from '@nestjs/common';
import { DashboardService } from './dashboard.service';

@Controller('api')
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
}

