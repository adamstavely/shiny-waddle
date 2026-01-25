import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  HttpStatus,
  HttpException,
} from '@nestjs/common';
import { MultiRegionTestingApiService, MultiRegionTestExecutionRequest } from './multi-region-testing.service';
import { PolicyConsistencyService } from './policy-consistency.service';
import { PolicySyncService } from './policy-sync.service';

@Controller('api/distributed')
export class DistributedController {
  constructor(
    private readonly multiRegionTestingService: MultiRegionTestingApiService,
    private readonly policyConsistencyService: PolicyConsistencyService,
    private readonly policySyncService: PolicySyncService,
  ) {}

  /**
   * Execute multi-region test
   */
  @Post('tests/multi-region/execute')
  async executeMultiRegionTest(@Body() request: MultiRegionTestExecutionRequest) {
    try {
      return await this.multiRegionTestingService.executeTest(request);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to execute multi-region test',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get multi-region test execution status
   */
  @Get('tests/multi-region/:testId/status')
  async getMultiRegionTestStatus(@Param('testId') testId: string) {
    try {
      return await this.multiRegionTestingService.getExecutionStatus(testId);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to get test status',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Run policy consistency check
   */
  @Post('tests/policy-consistency/check')
  async checkPolicyConsistency(@Body() request: any) {
    try {
      return await this.policyConsistencyService.checkConsistency(request);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to check policy consistency',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get policy consistency report
   */
  @Get('tests/policy-consistency/report/:reportId')
  async getPolicyConsistencyReport(@Param('reportId') reportId: string) {
    try {
      return await this.policyConsistencyService.getConsistencyReport(reportId);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to get consistency report',
        HttpStatus.NOT_FOUND
      );
    }
  }

  /**
   * Test policy synchronization
   */
  @Post('tests/policy-sync/test')
  async testPolicySynchronization(@Body() request: any) {
    try {
      return await this.policySyncService.testSynchronization(request);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to test policy synchronization',
        HttpStatus.INTERNAL_SERVER_ERROR
      );
    }
  }

  /**
   * Get policy synchronization report
   */
  @Get('tests/policy-sync/report/:reportId')
  async getPolicySyncReport(@Param('reportId') reportId: string) {
    try {
      return await this.policySyncService.getSyncReport(reportId);
    } catch (error: any) {
      throw new HttpException(
        error.message || 'Failed to get sync report',
        HttpStatus.NOT_FOUND
      );
    }
  }
}
