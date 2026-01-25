import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Query,
} from '@nestjs/common';
import { BatchOperationsService } from './batch-operations.service';
import { BatchFileDto } from './dto/batch-operation.dto';

@Controller('api/batch')
export class BatchOperationsController {
  constructor(private readonly batchOperationsService: BatchOperationsService) {}

  @Post('run')
  @HttpCode(HttpStatus.OK)
  async runBatch(
    @Body(ValidationPipe) batchFile: BatchFileDto,
    @Query('type') filterType?: 'test' | 'validate' | 'report',
  ) {
    return this.batchOperationsService.runBatchOperations(batchFile, filterType);
  }

  @Post('test')
  @HttpCode(HttpStatus.OK)
  async runBatchTest(@Body(ValidationPipe) batchFile: BatchFileDto) {
    return this.batchOperationsService.runBatchOperations(batchFile, 'test');
  }

  @Post('validate')
  @HttpCode(HttpStatus.OK)
  async runBatchValidate(@Body(ValidationPipe) batchFile: BatchFileDto) {
    return this.batchOperationsService.runBatchOperations(batchFile, 'validate');
  }

  @Post('report')
  @HttpCode(HttpStatus.OK)
  async runBatchReport(@Body(ValidationPipe) batchFile: BatchFileDto) {
    return this.batchOperationsService.runBatchOperations(batchFile, 'report');
  }

  @Post('parse')
  @HttpCode(HttpStatus.OK)
  async parseBatchFile(
    @Body('content') content: string,
    @Body('format') format: 'json' | 'yaml' = 'json',
  ) {
    return this.batchOperationsService.parseBatchFile(content, format);
  }
}
