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
}

