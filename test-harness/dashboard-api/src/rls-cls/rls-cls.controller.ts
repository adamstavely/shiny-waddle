import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { RLSCLSService } from './rls-cls.service';
import {
  TestRLSCoverageDto,
  TestCLSCoverageDto,
  TestDynamicMaskingDto,
  TestCrossTenantIsolationDto,
} from './dto/rls-cls.dto';
import { IsString, IsNotEmpty, IsOptional, ValidateIf } from 'class-validator';

class TestPolicyBypassDto {
  @IsOptional()
  @IsString()
  @ValidateIf((o) => !o.configId)
  @IsNotEmpty()
  userId?: string;

  @IsOptional()
  @IsString()
  @ValidateIf((o) => !o.configId)
  @IsNotEmpty()
  resourceId?: string;

  @IsOptional()
  @IsString()
  @ValidateIf((o) => !o.configId)
  @IsNotEmpty()
  resourceType?: string;
}

@Controller('api/rls-cls')
export class RLSCLSController {
  private readonly logger = new Logger(RLSCLSController.name);

  constructor(private readonly rlsClsService: RLSCLSService) {}

  @Post('test-rls-coverage')
  @HttpCode(HttpStatus.OK)
  async testRLSCoverage(@Body(ValidationPipe) dto: TestRLSCoverageDto) {
    this.logger.log(`Testing RLS coverage for database: ${dto.database?.database || 'unknown'}`);
    return this.rlsClsService.testRLSCoverage(dto);
  }

  @Post('test-cls-coverage')
  @HttpCode(HttpStatus.OK)
  async testCLSCoverage(@Body(ValidationPipe) dto: TestCLSCoverageDto) {
    this.logger.log(`Testing CLS coverage for database: ${dto.database?.database || 'unknown'}`);
    return this.rlsClsService.testCLSCoverage(dto);
  }

  @Post('test-dynamic-masking')
  @HttpCode(HttpStatus.OK)
  async testDynamicMasking(@Body(ValidationPipe) dto: TestDynamicMaskingDto & { configId?: string }) {
    this.logger.log(dto.configId
      ? `Testing dynamic masking with config: ${dto.configId}`
      : `Testing dynamic masking for query: ${dto.query?.name || 'unknown'}`);
    return this.rlsClsService.testDynamicMasking(dto);
  }

  @Post('test-cross-tenant-isolation')
  @HttpCode(HttpStatus.OK)
  async testCrossTenantIsolation(
    @Body(ValidationPipe) dto: TestCrossTenantIsolationDto,
  ) {
    this.logger.log(
      `Testing cross-tenant isolation: ${dto.tenant1} vs ${dto.tenant2}`,
    );
    return this.rlsClsService.testCrossTenantIsolation(dto);
  }

  @Post('test-policy-bypass')
  @HttpCode(HttpStatus.OK)
  async testPolicyBypass(@Body(ValidationPipe) dto: TestPolicyBypassDto & { configId?: string }) {
    this.logger.log(dto.configId
      ? `Testing policy bypass with config: ${dto.configId}`
      : `Testing policy bypass for user: ${dto.userId}, resource: ${dto.resourceId}`);
    return this.rlsClsService.testPolicyBypass(dto);
  }
}

