import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { NIST800207Service } from './nist-800-207.service';

@Controller('api/compliance/nist-800-207')
export class NIST800207Controller {
  private readonly logger = new Logger(NIST800207Controller.name);

  constructor(private readonly nist800207Service: NIST800207Service) {}

  @Post('assess')
  @HttpCode(HttpStatus.OK)
  async assess(@Body(ValidationPipe) dto: { assessment?: any }) {
    this.logger.log('Running NIST 800-207 ZTA compliance assessment');
    return this.nist800207Service.assessZTAPillars(dto.assessment || {});
  }

  @Post('report')
  @HttpCode(HttpStatus.OK)
  async generateReport(@Body(ValidationPipe) dto: { assessment: any }) {
    this.logger.log('Generating NIST 800-207 compliance report');
    return this.nist800207Service.generateComplianceReport(dto.assessment);
  }
}

