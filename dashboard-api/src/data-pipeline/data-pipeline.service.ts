import { Injectable, NotFoundException, Logger, Inject, forwardRef } from '@nestjs/common';
import { DataPipelineTester, PipelineTestConfig, PipelineTest } from '../../heimdall-framework/services/data-pipeline-tester';
import { ApplicationsService } from '../applications/applications.service';
import { DataPipelineInfrastructure } from '../applications/entities/application.entity';

@Injectable()
export class DataPipelineService {
  private readonly logger = new Logger(DataPipelineService.name);

  constructor(
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService,
  ) {}

  /**
   * Run Data Pipeline test - supports application infrastructure
   */
  async runTest(
    applicationId: string,
    context?: {
      buildId?: string;
      runId?: string;
      commitSha?: string;
      branch?: string;
    }
  ): Promise<any> {
    const application = await this.applicationsService.findOne(applicationId);
    
    if (!application.infrastructure?.dataPipeline) {
      throw new NotFoundException(`Application "${applicationId}" has no data pipeline infrastructure configured`);
    }
    
    const pipelineInfra = application.infrastructure.dataPipeline;

    const testerConfig: PipelineTestConfig = {
      pipelineType: pipelineInfra.pipelineType,
      connection: pipelineInfra.connection,
      dataSource: pipelineInfra.dataSource,
      dataDestination: pipelineInfra.dataDestination,
    };

    const tester = new DataPipelineTester(testerConfig);

    let result: any;

    try {
      const test: PipelineTest = {
        name: `Test: ${application.name} - Data Pipeline`,
        pipelineId: application.id,
        stage: 'all',
        expectedAccess: true,
      };

      switch (pipelineInfra.pipelineType) {
        case 'etl':
          result = await tester.testETLPipeline(test);
          break;

        case 'streaming':
          result = await tester.testStreamingData(test);
          break;

        case 'batch':
          // Batch processing uses ETL pipeline test
          result = await tester.testETLPipeline(test);
          break;

        case 'real-time':
          // Real-time processing uses streaming test
          result = await tester.testStreamingData(test);
          break;

        default:
          // Default to ETL
          result = await tester.testETLPipeline(test);
      }

      // Convert DataPipelineTester result to test configuration format
      const overallResult = {
        passed: result.passed !== false,
        testType: 'data-pipeline',
        testName: `Data Pipeline Test: ${application.name}`,
        timestamp: new Date(),
        details: {
          applicationId: application.id,
          applicationName: application.name,
          pipelineType: pipelineInfra.pipelineType,
          accessGranted: result.accessGranted,
          dataValidation: result.dataValidation,
          transformationResult: result.transformationResult,
          securityIssues: result.securityIssues,
          performanceMetrics: result.performanceMetrics,
          ...result.details,
        },
        ...context,
      };

      return overallResult;
    } catch (error: any) {
      this.logger.error(`Error executing data pipeline test: ${error.message}`, error.stack);
      return {
        passed: false,
        testType: 'data-pipeline',
        testName: `Data Pipeline Test: ${application.name}`,
        timestamp: new Date(),
        error: error.message,
        details: {
          applicationId: application.id,
          applicationName: application.name,
        },
        ...context,
      };
    }
  }
}

