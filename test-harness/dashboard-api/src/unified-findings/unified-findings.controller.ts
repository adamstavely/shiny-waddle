import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Body,
  Query,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { UnifiedFindingsService } from './unified-findings.service';
import { UnifiedFinding } from '../../../core/unified-finding-schema';
import { ScannerResult } from '../../../services/normalization-engine';

@Controller('api/unified-findings')
export class UnifiedFindingsController {
  constructor(private readonly service: UnifiedFindingsService) {}

  @Get()
  async getAllFindings(
    @Query('source') source?: string,
    @Query('scannerId') scannerId?: string,
    @Query('severity') severity?: string,
    @Query('status') status?: string,
    @Query('applicationId') applicationId?: string,
  ) {
    return this.service.getAllFindings({
      source,
      scannerId,
      severity,
      status,
      applicationId,
    });
  }

  @Get('statistics')
  async getStatistics() {
    return this.service.getStatistics();
  }

  @Get('ecs')
  async getFindingsAsECS(
    @Query('source') source?: string,
    @Query('scannerId') scannerId?: string,
    @Query('severity') severity?: string,
    @Query('status') status?: string,
  ) {
    return this.service.getFindingsAsECS({
      source,
      scannerId,
      severity,
      status,
    });
  }

  @Get(':id')
  async getFindingById(@Param('id') id: string) {
    const finding = await this.service.getFindingById(id);
    if (!finding) {
      throw new HttpException('Finding not found', HttpStatus.NOT_FOUND);
    }
    return finding;
  }

  @Post('normalize')
  async normalizeAndIngest(@Body() scannerResults: ScannerResult[]) {
    return this.service.normalizeAndIngest(scannerResults);
  }

  @Patch(':id')
  async updateFinding(
    @Param('id') id: string,
    @Body() updates: Partial<UnifiedFinding>
  ) {
    return this.service.updateFinding(id, updates);
  }

  @Delete(':id')
  async deleteFinding(@Param('id') id: string) {
    await this.service.deleteFinding(id);
    return { success: true };
  }

  /**
   * Schema versioning endpoints
   */
  @Get('schema/version')
  async getSchemaVersion(@Query('version') version?: string) {
    return this.service.getSchemaVersionInfo(version);
  }

  @Post('schema/detect')
  async detectVersion(@Body() finding: any) {
    return this.service.detectFindingVersion(finding);
  }

  @Post('schema/migrate')
  async migrateFinding(
    @Body() body: { finding: any; fromVersion?: string; toVersion?: string }
  ) {
    return this.service.migrateFinding(
      body.finding,
      body.fromVersion,
      body.toVersion
    );
  }

  @Post('schema/validate')
  async validateFinding(
    @Body() body: { finding: any; version?: string }
  ) {
    return this.service.validateFinding(body.finding, body.version);
  }

  /**
   * Risk Scoring & Prioritization endpoints
   */
  
  @Post(':id/risk-score')
  async calculateRiskScore(@Param('id') id: string) {
    return this.service.calculateRiskScore(id);
  }

  @Post('risk-scores/calculate-all')
  async calculateAllRiskScores() {
    return this.service.calculateAllRiskScores();
  }

  @Get('prioritized')
  async getPrioritizedFindings(@Query('limit') limit?: string) {
    const limitNum = limit ? parseInt(limit, 10) : undefined;
    return this.service.getPrioritizedFindings(limitNum);
  }

  @Get('risk-aggregation/application/:applicationId')
  async getApplicationRisk(@Param('applicationId') applicationId: string) {
    return this.service.aggregateRiskByApplication(applicationId);
  }

  @Get('risk-aggregation/team/:teamName')
  async getTeamRisk(@Param('teamName') teamName: string) {
    return this.service.aggregateRiskByTeam(teamName);
  }

  @Get('risk-aggregation/organization')
  async getOrganizationRisk() {
    return this.service.aggregateRiskByOrganization();
  }

  @Get('risk-trends')
  async getRiskTrends(@Query('periodDays') periodDays?: string) {
    const period = periodDays ? parseInt(periodDays, 10) : 30;
    return this.service.getRiskTrends(period);
  }

  /**
   * Correlation & Deduplication endpoints
   */

  @Post('correlate')
  async correlateFindings(
    @Query('source') source?: string,
    @Query('scannerId') scannerId?: string,
    @Query('severity') severity?: string,
    @Query('status') status?: string,
    @Query('applicationId') applicationId?: string,
  ) {
    return this.service.correlateFindings({
      source,
      scannerId,
      severity,
      status,
      applicationId,
    });
  }

  @Get(':id/related')
  async getRelatedFindings(@Param('id') id: string) {
    return this.service.getRelatedFindings(id);
  }

  /**
   * Attack Path Analysis endpoints
   */

  @Post('attack-paths/analyze')
  async analyzeAttackPaths(
    @Query('source') source?: string,
    @Query('scannerId') scannerId?: string,
    @Query('severity') severity?: string,
    @Query('status') status?: string,
    @Query('applicationId') applicationId?: string,
  ) {
    return this.service.analyzeAttackPaths({
      source,
      scannerId,
      severity,
      status,
      applicationId,
    });
  }

  @Get('attack-paths/application/:applicationId')
  async getApplicationAttackPaths(@Param('applicationId') applicationId: string) {
    return this.service.getApplicationAttackPaths(applicationId);
  }

  @Get('attack-paths/prioritized')
  async getAttackPathPrioritizedFindings(@Query('limit') limit?: string) {
    const limitNum = limit ? parseInt(limit, 10) : undefined;
    return this.service.getAttackPathPrioritizedFindings(limitNum);
  }
}

