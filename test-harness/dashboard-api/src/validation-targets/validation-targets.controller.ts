import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  ValidationPipe,
} from '@nestjs/common';
import { ValidationTargetsService } from './validation-targets.service';
import { CreateValidationTargetDto } from './dto/create-validation-target.dto';
import { UpdateValidationTargetDto } from './dto/update-validation-target.dto';
import { CreateValidationRuleDto } from './dto/create-validation-rule.dto';
import { ValidationTargetEntity, ValidationRuleEntity, ValidationResultEntity } from './entities/validation-target.entity';

@Controller('api/validation-targets')
export class ValidationTargetsController {
  constructor(private readonly service: ValidationTargetsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async createTarget(@Body(ValidationPipe) dto: CreateValidationTargetDto): Promise<ValidationTargetEntity> {
    return this.service.createTarget(dto);
  }

  @Get()
  async findAllTargets(): Promise<ValidationTargetEntity[]> {
    return this.service.findAllTargets();
  }

  @Get(':id')
  async findOneTarget(@Param('id') id: string): Promise<ValidationTargetEntity> {
    return this.service.findOneTarget(id);
  }

  @Patch(':id')
  async updateTarget(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateValidationTargetDto,
  ): Promise<ValidationTargetEntity> {
    return this.service.updateTarget(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeTarget(@Param('id') id: string): Promise<void> {
    return this.service.removeTarget(id);
  }

  @Post(':id/validate')
  @HttpCode(HttpStatus.OK)
  async runValidation(@Param('id') id: string): Promise<{ success: boolean; message: string; results: ValidationResultEntity[] }> {
    return this.service.runValidation(id);
  }

  @Get(':id/results')
  async getResults(@Param('id') id: string): Promise<ValidationResultEntity[]> {
    return this.service.findResultsByTarget(id);
  }

  @Get(':id/rules')
  async getRules(@Param('id') id: string): Promise<ValidationRuleEntity[]> {
    return this.service.findRulesByTarget(id);
  }

  @Post(':id/rules')
  @HttpCode(HttpStatus.CREATED)
  async createRule(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: CreateValidationRuleDto,
  ): Promise<ValidationRuleEntity> {
    return this.service.createRule({ ...dto, targetId: id });
  }
}

@Controller('api/validation-rules')
export class ValidationRulesController {
  constructor(private readonly service: ValidationTargetsService) {}

  @Get(':id')
  async findOneRule(@Param('id') id: string): Promise<ValidationRuleEntity> {
    return this.service.findOneRule(id);
  }

  @Patch(':id')
  async updateRule(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: Partial<CreateValidationRuleDto>,
  ): Promise<ValidationRuleEntity> {
    return this.service.updateRule(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeRule(@Param('id') id: string): Promise<void> {
    return this.service.removeRule(id);
  }

  @Get(':id/results')
  async getResults(@Param('id') id: string): Promise<ValidationResultEntity[]> {
    return this.service.findResultsByRule(id);
  }
}

