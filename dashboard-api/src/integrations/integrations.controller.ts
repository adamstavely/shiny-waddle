import { Controller, Get } from '@nestjs/common';
import { IntegrationsService } from './integrations.service';

@Controller('api/integrations')
export class IntegrationsController {
  constructor(private readonly service: IntegrationsService) {}

  @Get('status')
  async getStatus() {
    return this.service.getIntegrationStatus();
  }
}

