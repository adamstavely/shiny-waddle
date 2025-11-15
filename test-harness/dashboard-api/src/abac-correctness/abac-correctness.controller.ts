import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { ABACCorrectnessService } from './abac-correctness.service';
import {
  ValidateAttributesDto,
  CompletenessTestConfigDto,
  PerformanceTestConfigDto,
  ConflictTestConfigDto,
  PropagationTestConfigDto,
} from './dto/abac-correctness.dto';

@Controller('api/abac-correctness')
export class ABACCorrectnessController {
  private readonly logger = new Logger(ABACCorrectnessController.name);

  constructor(private readonly service: ABACCorrectnessService) {}

  @Post('validate-attributes')
  @HttpCode(HttpStatus.OK)
  async validateAttributes(@Body(ValidationPipe) dto: ValidateAttributesDto) {
    this.logger.log(`Validating ABAC attributes: ${dto.attributes?.length || 0} attributes`);
    return this.service.validateAttributes(dto);
  }

  @Post('test-completeness')
  @HttpCode(HttpStatus.OK)
  async testCompleteness(@Body(ValidationPipe) dto: CompletenessTestConfigDto) {
    this.logger.log(`Testing ABAC completeness: ${dto.policies?.length || 0} policies`);
    return this.service.testCompleteness(dto);
  }

  @Post('test-performance')
  @HttpCode(HttpStatus.OK)
  async testPerformance(@Body(ValidationPipe) dto: PerformanceTestConfigDto) {
    this.logger.log(`Testing ABAC performance: ${dto.policies?.length || 0} policies`);
    return this.service.testPerformance(dto);
  }

  @Post('detect-conflicts')
  @HttpCode(HttpStatus.OK)
  async detectConflicts(@Body(ValidationPipe) dto: ConflictTestConfigDto) {
    this.logger.log(`Detecting ABAC conflicts: ${dto.policies?.length || 0} policies`);
    return this.service.detectConflicts(dto);
  }

  @Post('test-propagation')
  @HttpCode(HttpStatus.OK)
  async testPropagation(@Body(ValidationPipe) dto: PropagationTestConfigDto) {
    this.logger.log(`Testing ABAC propagation: ${dto.sourceSystem} -> ${dto.targetSystems?.join(', ') || 'none'}`);
    return this.service.testPropagation(dto);
  }
}

