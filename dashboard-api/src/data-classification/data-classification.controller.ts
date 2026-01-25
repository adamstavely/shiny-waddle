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
import { DataClassificationService } from './data-classification.service';
import { CreateClassificationLevelDto } from './dto/create-classification-level.dto';
import { CreateClassificationRuleDto } from './dto/create-classification-rule.dto';

@Controller('api/v1/data-classification')
export class DataClassificationController {
  private readonly logger = new Logger(DataClassificationController.name);

  constructor(private readonly dataClassificationService: DataClassificationService) {}

  @Get('levels')
  @HttpCode(HttpStatus.OK)
  async getLevels() {
    this.logger.log('Fetching all classification levels');
    return this.dataClassificationService.getLevels();
  }

  @Post('levels')
  @HttpCode(HttpStatus.CREATED)
  async createLevel(@Body(ValidationPipe) dto: CreateClassificationLevelDto) {
    this.logger.log(`Creating classification level: ${dto.name}`);
    return this.dataClassificationService.createLevel(dto);
  }

  @Put('levels/:id')
  @HttpCode(HttpStatus.OK)
  async updateLevel(@Param('id') id: string, @Body(ValidationPipe) dto: Partial<CreateClassificationLevelDto>) {
    this.logger.log(`Updating classification level: ${id}`);
    return this.dataClassificationService.updateLevel(id, dto);
  }

  @Delete('levels/:id')
  @HttpCode(HttpStatus.OK)
  async deleteLevel(@Param('id') id: string) {
    this.logger.log(`Deleting classification level: ${id}`);
    return this.dataClassificationService.deleteLevel(id);
  }

  @Get('rules')
  @HttpCode(HttpStatus.OK)
  async getRules() {
    this.logger.log('Fetching all classification rules');
    return this.dataClassificationService.getRules();
  }

  @Post('rules')
  @HttpCode(HttpStatus.CREATED)
  async createRule(@Body(ValidationPipe) dto: CreateClassificationRuleDto) {
    this.logger.log(`Creating classification rule: ${dto.name}`);
    return this.dataClassificationService.createRule(dto);
  }

  @Put('rules/:id')
  @HttpCode(HttpStatus.OK)
  async updateRule(@Param('id') id: string, @Body(ValidationPipe) dto: Partial<CreateClassificationRuleDto>) {
    this.logger.log(`Updating classification rule: ${id}`);
    return this.dataClassificationService.updateRule(id, dto);
  }

  @Delete('rules/:id')
  @HttpCode(HttpStatus.OK)
  async deleteRule(@Param('id') id: string) {
    this.logger.log(`Deleting classification rule: ${id}`);
    return this.dataClassificationService.deleteRule(id);
  }
}

