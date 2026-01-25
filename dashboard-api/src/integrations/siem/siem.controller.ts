import { Controller, Get, Post, Put, Delete, Param, Body, Query, HttpStatus, HttpException } from '@nestjs/common';
import { SIEMService } from './siem.service';
import { SIEMConfig } from '../../../../heimdall-framework/services/siem-integration';
import { UnifiedFinding } from '../../../../heimdall-framework/core/unified-finding-schema';

@Controller('api/integrations/siem')
export class SIEMController {
  constructor(private readonly service: SIEMService) {}

  @Post()
  async createIntegration(@Body() config: SIEMConfig) {
    return this.service.createIntegration(config);
  }

  @Get()
  async findAllIntegrations() {
    return this.service.findAllIntegrations();
  }

  @Get(':type')
  async findOneIntegration(@Param('type') type: string) {
    return this.service.findOneIntegration(type);
  }

  @Put(':type')
  async updateIntegration(@Param('type') type: string, @Body() updates: Partial<SIEMConfig>) {
    return this.service.updateIntegration(type, updates);
  }

  @Delete(':type')
  async deleteIntegration(@Param('type') type: string) {
    await this.service.deleteIntegration(type);
    return { message: 'Integration deleted' };
  }

  @Post(':type/test')
  async testConnection(@Param('type') type: string) {
    const connected = await this.service.testConnection(type);
    return { connected };
  }

  @Post(':type/send')
  async sendFinding(@Param('type') type: string, @Body() finding: UnifiedFinding) {
    const success = await this.service.sendFinding(type, finding);
    return { success };
  }

  @Get(':type/query')
  async queryEvents(
    @Param('type') type: string,
    @Query('query') query: string,
    @Query('startTime') startTime?: string,
    @Query('endTime') endTime?: string,
  ) {
    return this.service.queryEvents(type, query, startTime, endTime);
  }
}

