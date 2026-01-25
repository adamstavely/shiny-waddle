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
import { ServiceNowBaselinesService } from './servicenow-baselines.service';
import { CreateServiceNowBaselineDto } from './dto/create-servicenow-baseline.dto';
import { UpdateServiceNowBaselineDto } from './dto/update-servicenow-baseline.dto';
import { CompareBaselineDto } from './dto/compare-baseline.dto';

@Controller('api/v1/servicenow/baselines')
export class ServiceNowBaselinesController {
  private readonly logger = new Logger(ServiceNowBaselinesController.name);

  constructor(private readonly serviceNowBaselinesService: ServiceNowBaselinesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getBaselines() {
    this.logger.log('Fetching all ServiceNow data protection baselines');
    return this.serviceNowBaselinesService.getBaselines();
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createBaseline(@Body(ValidationPipe) dto: CreateServiceNowBaselineDto) {
    this.logger.log(`Creating ServiceNow data protection baseline: ${dto.name}`);
    return this.serviceNowBaselinesService.createBaseline(dto);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getBaseline(@Param('id') id: string) {
    this.logger.log(`Fetching ServiceNow baseline: ${id}`);
    return this.serviceNowBaselinesService.getBaseline(id);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async updateBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateServiceNowBaselineDto
  ) {
    this.logger.log(`Updating ServiceNow baseline: ${id}`);
    return this.serviceNowBaselinesService.updateBaseline(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteBaseline(@Param('id') id: string) {
    this.logger.log(`Deleting ServiceNow baseline: ${id}`);
    return this.serviceNowBaselinesService.deleteBaseline(id);
  }

  @Post(':id/compare')
  @HttpCode(HttpStatus.OK)
  async compareBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Comparing ServiceNow baseline ${id} with current config`);
    return this.serviceNowBaselinesService.compareBaseline(id, dto.currentConfig);
  }

  @Post(':id/detect-drift')
  @HttpCode(HttpStatus.OK)
  async detectDrift(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Detecting drift for ServiceNow baseline ${id}`);
    return this.serviceNowBaselinesService.detectDrift(id, dto.currentConfig);
  }
}
