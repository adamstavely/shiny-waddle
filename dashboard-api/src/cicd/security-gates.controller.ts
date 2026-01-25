import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { SecurityGatesService } from './security-gates.service';

@Controller('api/cicd/security-gates')
export class SecurityGatesController {
  private readonly logger = new Logger(SecurityGatesController.name);

  constructor(private readonly securityGatesService: SecurityGatesService) {}

  @Post('validate-pre-merge')
  @HttpCode(HttpStatus.OK)
  async validatePreMerge(@Body(ValidationPipe) dto: { pr: any; policies: any[] }) {
    this.logger.log(
      `Validating pre-merge for PR: ${dto.pr?.id || 'unknown'} with ${dto.policies?.length || 0} policies`,
    );
    return this.securityGatesService.validatePreMerge(dto);
  }

  @Post('check-gates')
  @HttpCode(HttpStatus.OK)
  async checkGates(@Body(ValidationPipe) dto: { pr: any; config: any }) {
    this.logger.log(
      `Checking security gates for PR: ${dto.pr?.id || 'unknown'}, threshold: ${dto.config?.severityThreshold || 'unknown'}`,
    );
    return this.securityGatesService.checkGates(dto);
  }
}

