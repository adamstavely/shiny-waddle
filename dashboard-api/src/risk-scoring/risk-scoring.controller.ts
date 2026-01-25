import { Controller, Get, Post, Body, Query, Param } from '@nestjs/common';
import { EnhancedRiskScoringService, RiskHeatmapData, RiskTrend, AdvancedRiskScore } from './services/enhanced-risk-scoring.service';
import { TestResultsService } from '../test-results/test-results.service';

@Controller('api/v1/risk-scoring')
export class RiskScoringController {
  constructor(
    private readonly riskScoringService: EnhancedRiskScoringService,
    private readonly testResultsService: TestResultsService,
  ) {}

  @Get('heatmap')
  async getHeatmapData(
    @Query('applicationId') applicationId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ): Promise<RiskHeatmapData[]> {
    return this.riskScoringService.generateHeatmapData({
      applicationId,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });
  }

  @Get('trends')
  async getTrends(
    @Query('applicationId') applicationId?: string,
    @Query('testConfigurationId') testConfigurationId?: string,
    @Query('period') period?: 'day' | 'week' | 'month',
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ): Promise<RiskTrend[]> {
    return this.riskScoringService.calculateTrends({
      applicationId,
      testConfigurationId,
      period,
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
    });
  }

  @Post('calculate')
  async calculateRiskScores(
    @Body('testResultIds') testResultIds?: string[],
    @Body('applicationId') applicationId?: string,
    @Body('testConfigurationId') testConfigurationId?: string,
  ): Promise<AdvancedRiskScore[]> {
    let testResults;

    if (testResultIds && testResultIds.length > 0) {
      // Calculate for specific test results
      testResults = await Promise.all(
        testResultIds.map(id => this.testResultsService.findById(id))
      );
    } else {
      // Calculate for all matching criteria
      testResults = await this.testResultsService.query({
        applicationId,
        testConfigurationId,
      });
    }

    // Filter to only failed results
    const failedResults = testResults.filter(r => !r.passed);

    return this.riskScoringService.calculateRiskScores(failedResults);
  }

  @Get('application/:applicationId')
  async getApplicationRiskScores(
    @Param('applicationId') applicationId: string,
  ): Promise<AdvancedRiskScore[]> {
    const testResults = await this.testResultsService.query({
      applicationId,
    });

    const failedResults = testResults.filter(r => !r.passed);
    return this.riskScoringService.calculateRiskScores(failedResults);
  }
}

