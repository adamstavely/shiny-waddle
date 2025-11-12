import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { PolicyValidationService } from './policy-validation.service';
import {
  DetectConflictsDto,
  AnalyzeCoverageDto,
  TestPerformanceDto,
  RunRegressionDto,
  SimulatePolicyDto,
} from './dto/policy-validation.dto';

@Controller('api/policy-validation')
export class PolicyValidationController {
  private readonly logger = new Logger(PolicyValidationController.name);

  constructor(private readonly policyValidationService: PolicyValidationService) {}

  @Post('detect-conflicts')
  @HttpCode(HttpStatus.OK)
  async detectConflicts(@Body(ValidationPipe) dto: DetectConflictsDto) {
    this.logger.log(`Detecting conflicts for ${dto.policies?.length || 0} policies`);
    return this.policyValidationService.detectConflicts(dto);
  }

  @Post('analyze-coverage')
  @HttpCode(HttpStatus.OK)
  async analyzeCoverage(@Body(ValidationPipe) dto: AnalyzeCoverageDto) {
    this.logger.log(
      `Analyzing coverage for ${dto.resources?.length || 0} resources and ${dto.policies?.length || 0} policies`,
    );
    return this.policyValidationService.analyzeCoverage(dto);
  }

  @Post('test-performance')
  @HttpCode(HttpStatus.OK)
  async testPerformance(@Body(ValidationPipe) dto: TestPerformanceDto) {
    this.logger.log(`Testing performance for policy: ${dto.policy?.id || 'unknown'}`);
    return this.policyValidationService.testPerformance(dto);
  }

  @Post('run-regression')
  @HttpCode(HttpStatus.OK)
  async runRegression(@Body(ValidationPipe) dto: RunRegressionDto) {
    this.logger.log(
      `Running regression tests with ${dto.testCases?.length || 0} test cases`,
    );
    return this.policyValidationService.runRegression(dto);
  }

  @Post('simulate-policy')
  @HttpCode(HttpStatus.OK)
  async simulatePolicy(@Body(ValidationPipe) dto: SimulatePolicyDto) {
    this.logger.log(`Simulating policy: ${dto.policy?.id || 'unknown'}`);
    return this.policyValidationService.simulatePolicy(dto);
  }
}

