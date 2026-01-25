import { Controller, Get, Post, Body, Param, HttpCode, HttpStatus, ValidationPipe } from '@nestjs/common';
import { DataPipelineService } from './data-pipeline.service';

@Controller('api/data-pipeline')
export class DataPipelineController {
  constructor(private readonly dataPipelineService: DataPipelineService) {}

  @Post('applications/:applicationId/test')
  @HttpCode(HttpStatus.OK)
  async runTest(
    @Param('applicationId') applicationId: string,
    @Body(ValidationPipe) context?: {
      buildId?: string;
      runId?: string;
      commitSha?: string;
      branch?: string;
    }
  ) {
    return this.dataPipelineService.runTest(applicationId, context);
  }
}

