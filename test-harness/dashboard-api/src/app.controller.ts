import { Controller, Get } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  getRoot() {
    return {
      message: 'Heimdall Dashboard API',
      version: '1.0.0',
      endpoints: {
        dashboardData: '/api/dashboard-data',
        reports: '/api/reports',
      },
      frontend: 'http://localhost:5173',
      note: 'Access the dashboard UI at http://localhost:5173',
    };
  }
}

