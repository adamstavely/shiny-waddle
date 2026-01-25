import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Body,
  HttpCode,
  HttpStatus,
  Logger,
  ValidationPipe,
} from '@nestjs/common';
import { ElasticBaselinesService } from './elastic-baselines.service';
import { CreateElasticBaselineDto } from './dto/create-elastic-baseline.dto';
import { UpdateElasticBaselineDto } from './dto/update-elastic-baseline.dto';
import { CompareBaselineDto } from './dto/compare-baseline.dto';

@Controller('api/v1/elastic/baselines')
export class ElasticBaselinesController {
  private readonly logger = new Logger(ElasticBaselinesController.name);

  constructor(private readonly elasticBaselinesService: ElasticBaselinesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getBaselines() {
    this.logger.log('Fetching all Elastic data protection baselines');
    return this.elasticBaselinesService.getBaselines();
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createBaseline(@Body(ValidationPipe) dto: CreateElasticBaselineDto) {
    this.logger.log(`Creating Elastic data protection baseline: ${dto.name}`);
    return this.elasticBaselinesService.createBaseline(dto);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getBaseline(@Param('id') id: string) {
    this.logger.log(`Fetching Elastic baseline: ${id}`);
    return this.elasticBaselinesService.getBaseline(id);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async updateBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateElasticBaselineDto
  ) {
    this.logger.log(`Updating Elastic baseline: ${id}`);
    return this.elasticBaselinesService.updateBaseline(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteBaseline(@Param('id') id: string) {
    this.logger.log(`Deleting Elastic baseline: ${id}`);
    return this.elasticBaselinesService.deleteBaseline(id);
  }

  @Post(':id/compare')
  @HttpCode(HttpStatus.OK)
  async compareBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Comparing Elastic baseline ${id} with current config`);
    return this.elasticBaselinesService.compareBaseline(id, dto.currentConfig);
  }

  @Post(':id/detect-drift')
  @HttpCode(HttpStatus.OK)
  async detectDrift(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Detecting drift for Elastic baseline ${id}`);
    return this.elasticBaselinesService.detectDrift(id, dto.currentConfig);
  }
}
