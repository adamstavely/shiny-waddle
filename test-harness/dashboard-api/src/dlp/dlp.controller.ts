import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { DLPService } from './dlp.service';

@Controller('api/dlp')
export class DLPController {
  private readonly logger = new Logger(DLPController.name);

  constructor(private readonly dlpService: DLPService) {}

  @Post('test-exfiltration')
  @HttpCode(HttpStatus.OK)
  async testExfiltration(@Body(ValidationPipe) dto: { applicationId?: string; user?: any; dataOperation?: any }) {
    this.logger.log(dto.applicationId
      ? `Testing exfiltration for application: ${dto.applicationId}`
      : `Testing exfiltration for user: ${dto.user?.id || 'unknown'}, operation: ${dto.dataOperation?.type || 'unknown'}`);
    return this.dlpService.testExfiltration(dto);
  }

  @Post('validate-api-response')
  @HttpCode(HttpStatus.OK)
  async validateAPIResponse(
    @Body(ValidationPipe) dto: { applicationId?: string; apiResponse: any; allowedFields?: string[]; piiFields?: string[] },
  ) {
    this.logger.log(dto.applicationId
      ? `Validating API response for application: ${dto.applicationId}`
      : `Validating API response with ${dto.allowedFields?.length || 0} allowed fields and ${dto.piiFields?.length || 0} PII fields`);
    return this.dlpService.validateAPIResponse(dto);
  }

  @Post('test-query-validation')
  @HttpCode(HttpStatus.OK)
  async testQueryValidation(
    @Body(ValidationPipe) dto: { applicationId?: string; query: any; user: any; expectedFields?: string[] },
  ) {
    this.logger.log(dto.applicationId
      ? `Testing query validation for application: ${dto.applicationId}`
      : `Testing query validation for user: ${dto.user?.id || 'unknown'} with ${dto.expectedFields?.length || 0} expected fields`);
    return this.dlpService.testQueryValidation(dto);
  }

  @Post('test-bulk-export')
  @HttpCode(HttpStatus.OK)
  async testBulkExport(@Body(ValidationPipe) dto: { applicationId?: string; user?: any; exportRequest?: any }) {
    this.logger.log(dto.applicationId
      ? `Testing bulk export for application: ${dto.applicationId}`
      : `Testing bulk export for user: ${dto.user?.id || 'unknown'}, type: ${dto.exportRequest?.type || 'unknown'}, records: ${dto.exportRequest?.recordCount || 0}`);
    return this.dlpService.testBulkExport(dto);
  }
}

