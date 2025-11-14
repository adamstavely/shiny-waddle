import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Param,
  Query,
  Body,
  HttpCode,
  HttpStatus,
  Logger,
  ParseIntPipe,
  ValidationPipe,
} from '@nestjs/common';
import { TestResultsService } from './test-results.service';
import { TestResultEntity, TestResultStatus } from './entities/test-result.entity';

@Controller('api/test-results')
export class TestResultsController {
  private readonly logger = new Logger(TestResultsController.name);

  constructor(private readonly testResultsService: TestResultsService) {}

  @Get()
  async query(
    @Query('applicationId') applicationId?: string,
    @Query('testConfigurationId') testConfigurationId?: string,
    @Query('testHarnessId') testHarnessId?: string,
    @Query('testBatteryId') testBatteryId?: string,
    @Query('buildId') buildId?: string,
    @Query('branch') branch?: string,
    @Query('status') status?: TestResultStatus,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): Promise<TestResultEntity[]> {
    this.logger.log('Querying test results');
    
    const filters: any = {};
    if (applicationId) filters.applicationId = applicationId;
    if (testConfigurationId) filters.testConfigurationId = testConfigurationId;
    if (testHarnessId) filters.testHarnessId = testHarnessId;
    if (testBatteryId) filters.testBatteryId = testBatteryId;
    if (buildId) filters.buildId = buildId;
    if (branch) filters.branch = branch;
    if (status) filters.status = status;
    if (startDate) filters.startDate = new Date(startDate);
    if (endDate) filters.endDate = new Date(endDate);
    if (limit) filters.limit = parseInt(limit, 10);
    if (offset) filters.offset = parseInt(offset, 10);

    return this.testResultsService.query(filters);
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestResultEntity> {
    this.logger.log(`Getting test result: ${id}`);
    return this.testResultsService.findById(id);
  }

  @Get('application/:appId')
  async findByApplication(
    @Param('appId') appId: string,
    @Query('status') status?: TestResultStatus,
    @Query('branch') branch?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): Promise<TestResultEntity[]> {
    this.logger.log(`Getting test results for application: ${appId}`);
    return this.testResultsService.findByApplication(appId, {
      status,
      branch,
      limit: limit ? parseInt(limit, 10) : undefined,
      offset: offset ? parseInt(offset, 10) : undefined,
    });
  }

  @Get('test-configuration/:configId')
  async findByTestConfiguration(
    @Param('configId') configId: string,
    @Query('status') status?: TestResultStatus,
    @Query('branch') branch?: string,
    @Query('limit') limit?: string,
    @Query('offset') offset?: string,
  ): Promise<TestResultEntity[]> {
    this.logger.log(`Getting test results for test configuration: ${configId}`);
    return this.testResultsService.findByTestConfiguration(configId, {
      status,
      branch,
      limit: limit ? parseInt(limit, 10) : undefined,
      offset: offset ? parseInt(offset, 10) : undefined,
    });
  }

  @Get('build/:buildId')
  async findByBuild(@Param('buildId') buildId: string): Promise<TestResultEntity[]> {
    this.logger.log(`Getting test results for build: ${buildId}`);
    return this.testResultsService.findByBuild(buildId);
  }

  @Get('compliance/metrics')
  async getComplianceMetrics(
    @Query('applicationId') applicationId?: string,
    @Query('testConfigurationId') testConfigurationId?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ): Promise<any> {
    this.logger.log('Getting compliance metrics');
    
    const dateRange = (startDate || endDate) ? {
      start: startDate ? new Date(startDate) : new Date(0),
      end: endDate ? new Date(endDate) : new Date(),
    } : undefined;

    return this.testResultsService.getComplianceMetrics(
      applicationId,
      testConfigurationId,
      dateRange,
    );
  }

  @Get('compliance/trends')
  async getComplianceTrends(
    @Query('applicationId') applicationId?: string,
    @Query('testConfigurationId') testConfigurationId?: string,
    @Query('period') period?: 'day' | 'week' | 'month',
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
  ): Promise<Array<{ period: string; passRate: number; totalTests: number }>> {
    this.logger.log('Getting compliance trends');
    return this.testResultsService.getTrends(applicationId, testConfigurationId, period || 'day');
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test result: ${id}`);
    await this.testResultsService.delete(id);
  }

  @Post(':id/accept-risk')
  async acceptRisk(
    @Param('id') id: string,
    @Body(ValidationPipe) body: {
      reason: string;
      approver: string;
      expirationDate?: string;
      ticketLink?: string;
    },
  ): Promise<TestResultEntity> {
    this.logger.log(`Accepting risk for test result: ${id}`);
    return this.testResultsService.acceptRisk(id, {
      reason: body.reason,
      approver: body.approver,
      expirationDate: body.expirationDate ? new Date(body.expirationDate) : undefined,
      ticketLink: body.ticketLink,
    });
  }

  @Post(':id/reject-risk')
  async rejectRisk(
    @Param('id') id: string,
    @Body(ValidationPipe) body: {
      reason: string;
      approver: string;
    },
  ): Promise<TestResultEntity> {
    this.logger.log(`Rejecting risk for test result: ${id}`);
    return this.testResultsService.rejectRisk(id, {
      reason: body.reason,
      approver: body.approver,
    });
  }

  @Put(':id/remediation')
  async updateRemediation(
    @Param('id') id: string,
    @Body(ValidationPipe) body: {
      status?: 'not-started' | 'in-progress' | 'completed';
      ticketLink?: string;
      assignedTo?: string;
      targetDate?: string;
      notes?: string;
      progress?: number;
      steps?: Array<{
        step: string;
        status: 'pending' | 'in-progress' | 'completed';
        completedAt?: string;
      }>;
    },
  ): Promise<TestResultEntity> {
    this.logger.log(`Updating remediation for test result: ${id}`);
    return this.testResultsService.updateRemediation(id, {
      status: body.status,
      ticketLink: body.ticketLink,
      assignedTo: body.assignedTo,
      targetDate: body.targetDate ? new Date(body.targetDate) : undefined,
      notes: body.notes,
      progress: body.progress,
      steps: body.steps?.map(step => ({
        ...step,
        completedAt: step.completedAt ? new Date(step.completedAt) : undefined,
      })),
    });
  }
}

