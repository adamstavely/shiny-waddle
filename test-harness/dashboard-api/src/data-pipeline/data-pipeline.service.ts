import { Injectable, NotFoundException, Logger, Inject, forwardRef } from '@nestjs/common';
import { DataPipelineTester, PipelineTestConfig, PipelineTest } from '../../../services/data-pipeline-tester';
import { DataPipelineConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';

@Injectable()
export class DataPipelineService {
  private readonly logger = new Logger(DataPipelineService.name);

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly testConfigurationsService: TestConfigurationsService,
  ) {}

  async findOneConfig(id: string): Promise<DataPipelineConfigurationEntity> {
    const config = await this.testConfigurationsService.findOne(id);
    if (config.type !== 'data-pipeline') {
      throw new NotFoundException(`Configuration with ID "${id}" is not a data pipeline configuration`);
    }
    return config as DataPipelineConfigurationEntity;
  }

  /**
   * Run Data Pipeline test for test configuration system
   */
  async runTest(
    configId: string,
    context?: {
      applicationId?: string;
      buildId?: string;
      runId?: string;
      commitSha?: string;
      branch?: string;
    }
  ): Promise<any> {
    const config = await this.findOneConfig(configId);

    const testerConfig: PipelineTestConfig = {
      pipelineType: config.pipelineType,
      connection: config.connection,
      dataSource: config.dataSource,
      dataDestination: config.dataDestination,
    };

    const tester = new DataPipelineTester(testerConfig);

    let result: any;

    try {
      const test: PipelineTest = {
        name: `Test: ${config.name}`,
        pipelineId: config.id,
        stage: 'all',
        expectedAccess: true,
      };

      switch (config.pipelineType) {
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
        testName: `Data Pipeline Test: ${config.name}`,
        timestamp: new Date(),
        details: {
          configId: config.id,
          configName: config.name,
          pipelineType: config.pipelineType,
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
        testName: `Data Pipeline Test: ${config.name}`,
        timestamp: new Date(),
        error: error.message,
        details: {
          configId: config.id,
          configName: config.name,
        },
        ...context,
      };
    }
  }
}

