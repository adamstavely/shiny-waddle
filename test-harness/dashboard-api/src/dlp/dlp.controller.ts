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
  async testExfiltration(@Body(ValidationPipe) dto: { user: any; dataOperation: any }) {
    this.logger.log(
      `Testing exfiltration for user: ${dto.user?.id || 'unknown'}, operation: ${dto.dataOperation?.type || 'unknown'}`,
    );
    return this.dlpService.testExfiltration(dto);
  }

  @Post('validate-api-response')
  @HttpCode(HttpStatus.OK)
  async validateAPIResponse(
    @Body(ValidationPipe) dto: { apiResponse: any; allowedFields: string[]; piiFields: string[] },
  ) {
    this.logger.log(
      `Validating API response with ${dto.allowedFields?.length || 0} allowed fields and ${dto.piiFields?.length || 0} PII fields`,
    );
    return this.dlpService.validateAPIResponse(dto);
  }

  @Post('test-query-validation')
  @HttpCode(HttpStatus.OK)
  async testQueryValidation(
    @Body(ValidationPipe) dto: { query: any; user: any; expectedFields: string[] },
  ) {
    this.logger.log(
      `Testing query validation for user: ${dto.user?.id || 'unknown'} with ${dto.expectedFields?.length || 0} expected fields`,
    );
    return this.dlpService.testQueryValidation(dto);
  }

  @Post('test-bulk-export')
  @HttpCode(HttpStatus.OK)
  async testBulkExport(@Body(ValidationPipe) dto: { user: any; exportRequest: any }) {
    this.logger.log(
      `Testing bulk export for user: ${dto.user?.id || 'unknown'}, type: ${dto.exportRequest?.type || 'unknown'}, records: ${dto.exportRequest?.recordCount || 0}`,
    );
    return this.dlpService.testBulkExport(dto);
  }
}

