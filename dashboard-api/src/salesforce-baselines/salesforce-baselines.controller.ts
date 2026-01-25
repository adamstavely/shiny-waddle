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
import { SalesforceBaselinesService } from './salesforce-baselines.service';
import { CreateSalesforceBaselineDto } from './dto/create-salesforce-baseline.dto';
import { UpdateSalesforceBaselineDto } from './dto/update-salesforce-baseline.dto';
import { CompareBaselineDto } from './dto/compare-baseline.dto';

@Controller('api/v1/salesforce/baselines')
export class SalesforceBaselinesController {
  private readonly logger = new Logger(SalesforceBaselinesController.name);

  constructor(private readonly salesforceBaselinesService: SalesforceBaselinesService) {}

  @Get()
  @HttpCode(HttpStatus.OK)
  async getBaselines() {
    this.logger.log('Fetching all Salesforce data protection baselines');
    return this.salesforceBaselinesService.getBaselines();
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createBaseline(@Body(ValidationPipe) dto: CreateSalesforceBaselineDto) {
    this.logger.log(`Creating Salesforce data protection baseline: ${dto.name}`);
    return this.salesforceBaselinesService.createBaseline(dto);
  }

  @Get(':id')
  @HttpCode(HttpStatus.OK)
  async getBaseline(@Param('id') id: string) {
    this.logger.log(`Fetching Salesforce baseline: ${id}`);
    return this.salesforceBaselinesService.getBaseline(id);
  }

  @Put(':id')
  @HttpCode(HttpStatus.OK)
  async updateBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateSalesforceBaselineDto
  ) {
    this.logger.log(`Updating Salesforce baseline: ${id}`);
    return this.salesforceBaselinesService.updateBaseline(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async deleteBaseline(@Param('id') id: string) {
    this.logger.log(`Deleting Salesforce baseline: ${id}`);
    return this.salesforceBaselinesService.deleteBaseline(id);
  }

  @Post(':id/compare')
  @HttpCode(HttpStatus.OK)
  async compareBaseline(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Comparing Salesforce baseline ${id} with current config`);
    return this.salesforceBaselinesService.compareBaseline(id, dto.currentConfig);
  }

  @Post(':id/detect-drift')
  @HttpCode(HttpStatus.OK)
  async detectDrift(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CompareBaselineDto
  ) {
    this.logger.log(`Detecting drift for Salesforce baseline ${id}`);
    return this.salesforceBaselinesService.detectDrift(id, dto.currentConfig);
  }
}
