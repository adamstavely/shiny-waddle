import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { EnvironmentConfigService } from './environment-config.service';
import {
  ValidateEnvironmentDto,
  ValidateSecretsDto,
  DetectDriftDto,
  ValidateEnvironmentPoliciesDto,
} from './dto/environment-config.dto';

@Controller('api/environment-config')
export class EnvironmentConfigController {
  private readonly logger = new Logger(EnvironmentConfigController.name);

  constructor(private readonly service: EnvironmentConfigService) {}

  @Post('validate')
  @HttpCode(HttpStatus.OK)
  async validateEnvironment(@Body(ValidationPipe) dto: ValidateEnvironmentDto) {
    this.logger.log(`Validating environment: ${dto.environment}`);
    return this.service.validateEnvironment(dto);
  }

  @Post('validate-secrets')
  @HttpCode(HttpStatus.OK)
  async validateSecrets(@Body(ValidationPipe) dto: ValidateSecretsDto) {
    this.logger.log(`Validating secrets management: ${dto.type}`);
    return this.service.validateSecrets(dto);
  }

  @Post('detect-drift')
  @HttpCode(HttpStatus.OK)
  async detectDrift(@Body(ValidationPipe) dto: DetectDriftDto) {
    this.logger.log(`Detecting configuration drift: ${dto.baselineEnvironment} -> ${dto.currentEnvironment}`);
    return this.service.detectDrift(dto);
  }

  @Post('validate-policies')
  @HttpCode(HttpStatus.OK)
  async validateEnvironmentPolicies(@Body(ValidationPipe) dto: ValidateEnvironmentPoliciesDto) {
    this.logger.log(`Validating environment policies: ${dto.environment}`);
    return this.service.validateEnvironmentPolicies(dto);
  }
}

