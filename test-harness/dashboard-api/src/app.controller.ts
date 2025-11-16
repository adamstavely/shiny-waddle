import { Controller, Get } from '@nestjs/common';
import { Public } from './auth/decorators/public.decorator';

@Controller()
export class AppController {
  @Public()
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

