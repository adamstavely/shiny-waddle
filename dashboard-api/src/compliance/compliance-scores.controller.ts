import { Controller, Get, Query, HttpCode, HttpStatus, Logger } from '@nestjs/common';
import { ComplianceScoresService } from './compliance-scores.service';

@Controller('api/v1/compliance-scores')
export class ComplianceScoresController {
  private readonly logger = new Logger(ComplianceScoresController.name);

  constructor(private readonly complianceScoresService: ComplianceScoresService) {}

  @Get('history')
  @HttpCode(HttpStatus.OK)
  async getHistory(
    @Query('applicationId') applicationId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('days') days?: string,
    @Query('domain') domain?: string,
  ) {
    this.logger.log(`Getting compliance score history: ${JSON.stringify({ applicationId, startDate, endDate, days, domain })}`);
    return this.complianceScoresService.getHistory({
      applicationId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      days: days ? parseInt(days, 10) : undefined,
      domain,
    });
  }
}

