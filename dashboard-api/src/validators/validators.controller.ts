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
  Query,
  ValidationPipe,
} from '@nestjs/common';
import { ValidatorsService } from './validators.service';
import { CreateValidatorDto } from './dto/create-validator.dto';
import { UpdateValidatorDto } from './dto/update-validator.dto';
import { ValidatorEntity } from './entities/validator.entity';

@Controller('api/validators')
export class ValidatorsController {
  constructor(private readonly validatorsService: ValidatorsService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body(ValidationPipe) createValidatorDto: CreateValidatorDto): Promise<ValidatorEntity> {
    return this.validatorsService.create(createValidatorDto);
  }

  @Get()
  async findAll(
    @Query('testType') testType?: string,
    @Query('enabled') enabled?: string,
  ): Promise<ValidatorEntity[]> {
    if (testType) {
      return this.validatorsService.findByType(testType);
    }
    if (enabled === 'true') {
      return this.validatorsService.findEnabled();
    }
    return this.validatorsService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<ValidatorEntity> {
    return this.validatorsService.findOne(id);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) updateValidatorDto: UpdateValidatorDto,
  ): Promise<ValidatorEntity> {
    return this.validatorsService.update(id, updateValidatorDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string): Promise<void> {
    return this.validatorsService.remove(id);
  }

  @Post(':id/test')
  @HttpCode(HttpStatus.OK)
  async testConnection(@Param('id') id: string): Promise<{ success: boolean; message: string }> {
    return this.validatorsService.testConnection(id);
  }

  @Patch(':id/enable')
  @HttpCode(HttpStatus.OK)
  async enable(@Param('id') id: string): Promise<ValidatorEntity> {
    return this.validatorsService.enable(id);
  }

  @Patch(':id/disable')
  @HttpCode(HttpStatus.OK)
  async disable(@Param('id') id: string): Promise<ValidatorEntity> {
    return this.validatorsService.disable(id);
  }

  @Post('discover')
  @HttpCode(HttpStatus.OK)
  async discover(): Promise<{ message: string; discovered: number }> {
    return this.validatorsService.discoverAndRegisterValidators();
  }
}

