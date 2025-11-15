import { Controller, Get, Post, Body, Param, HttpCode, HttpStatus, ValidationPipe } from '@nestjs/common';
import { DataPipelineService } from './data-pipeline.service';

@Controller('api/data-pipeline')
export class DataPipelineController {
  constructor(private readonly dataPipelineService: DataPipelineService) {}

  @Get('configs/:id')
  async findOneConfig(@Param('id') id: string) {
    return this.dataPipelineService.findOneConfig(id);
  }

  @Post('configs/:id/test')
  @HttpCode(HttpStatus.OK)
  async runTest(
    @Param('id') id: string,
    @Body(ValidationPipe) context?: {
      applicationId?: string;
      buildId?: string;
      runId?: string;
      commitSha?: string;
      branch?: string;
    }
  ) {
    return this.dataPipelineService.runTest(id, context);
  }
}

