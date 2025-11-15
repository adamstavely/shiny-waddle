import { Injectable, NotFoundException, BadRequestException, Logger, Inject, forwardRef } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import {
  TestConfigurationEntity,
  TestConfigurationType,
  RLSCLSConfigurationEntity,
  NetworkPolicyConfigurationEntity,
  DLPConfigurationEntity,
  APIGatewayConfigurationEntity,
  DistributedSystemsConfigurationEntity,
  APISecurityConfigurationEntity,
  DataPipelineConfigurationEntity,
} from './entities/test-configuration.entity';
import {
  CreateTestConfigurationDto,
  CreateRLSCLSConfigurationDto,
  CreateNetworkPolicyConfigurationDto,
  CreateDLPConfigurationDto,
  CreateAPIGatewayConfigurationDto,
  CreateDistributedSystemsConfigurationDto,
  CreateAPISecurityConfigurationDto,
  CreateDataPipelineConfigurationDto,
} from './dto/create-test-configuration.dto';
import { RLSCLSService } from '../rls-cls/rls-cls.service';
import { DLPService } from '../dlp/dlp.service';
import { APIGatewayService } from '../api-gateway/api-gateway.service';
import { NetworkPolicyService } from '../network-policy/network-policy.service';
import { DistributedSystemsService } from '../distributed-systems/distributed-systems.service';
import { ApiSecurityService } from '../api-security/api-security.service';
import { DataPipelineService } from '../data-pipeline/data-pipeline.service';
import { ApplicationsService } from '../applications/applications.service';
import { TestResultsService } from '../test-results/test-results.service';
import { TestResultStatus } from '../test-results/entities/test-result.entity';

@Injectable()
export class TestConfigurationsService {
  private readonly logger = new Logger(TestConfigurationsService.name);
  private readonly configsFile = path.join(process.cwd(), 'data', 'test-configurations.json');
  private configurations: TestConfigurationEntity[] = [];

  constructor(
    @Inject(forwardRef(() => RLSCLSService))
    private readonly rlsClsService: RLSCLSService,
    @Inject(forwardRef(() => DLPService))
    private readonly dlpService: DLPService,
    @Inject(forwardRef(() => APIGatewayService))
    private readonly apiGatewayService: APIGatewayService,
    @Inject(forwardRef(() => NetworkPolicyService))
    private readonly networkPolicyService: NetworkPolicyService,
    @Inject(forwardRef(() => DistributedSystemsService))
    private readonly distributedSystemsService: DistributedSystemsService,
    @Inject(forwardRef(() => ApiSecurityService))
    private readonly apiSecurityService: ApiSecurityService,
    @Inject(forwardRef(() => DataPipelineService))
    private readonly dataPipelineService: DataPipelineService,
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService,
    @Inject(forwardRef(() => TestResultsService))
    private readonly testResultsService: TestResultsService,
  ) {
    this.loadConfigurations().catch(err => {
      this.logger.error('Error loading test configurations on startup:', err);
    });
  }

  private async loadConfigurations(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.configsFile, 'utf-8');
        if (!data || data.trim() === '') {
          // Empty file, initialize defaults
          this.configurations = [];
          await this.initializeDefaultConfigurations();
          await this.saveConfigurations();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Configurations file does not contain an array, initializing defaults');
          this.configurations = [];
          await this.initializeDefaultConfigurations();
          await this.saveConfigurations();
          return;
        }
        this.configurations = parsed.map((c: any) => ({
          ...c,
          createdAt: c.createdAt ? new Date(c.createdAt) : new Date(),
          updatedAt: c.updatedAt ? new Date(c.updatedAt) : new Date(),
          enabled: c.enabled !== undefined ? c.enabled : true, // Default to enabled for existing configs
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          // File doesn't exist, initialize defaults
          this.configurations = [];
          await this.initializeDefaultConfigurations();
          await this.saveConfigurations();
        } else if (readError instanceof SyntaxError) {
          // JSON parsing error - file is corrupted
          this.logger.error('JSON parsing error in configurations file, initializing defaults:', readError.message);
          this.configurations = [];
          await this.initializeDefaultConfigurations();
          await this.saveConfigurations();
        } else {
          throw readError;
        }
      }
      
      // Initialize defaults if no configurations exist
      if (this.configurations.length === 0) {
        await this.initializeDefaultConfigurations();
        await this.saveConfigurations();
      }
    } catch (error) {
      this.logger.error('Error loading test configurations:', error);
      // Ensure we have at least an empty array
      if (!this.configurations) {
        this.configurations = [];
      }
      // Don't throw - allow service to continue with empty array
    }
  }

  private async initializeDefaultConfigurations(): Promise<void> {
    const now = new Date();
    
    // Default RLS/CLS Configuration
    const defaultRLSCLS: RLSCLSConfigurationEntity = {
      id: uuidv4(),
      name: 'Default PostgreSQL RLS/CLS',
      type: 'rls-cls',
      description: 'Default configuration for PostgreSQL RLS/CLS testing',
      database: {
        type: 'postgresql',
        host: 'localhost',
        port: 5432,
        database: 'test',
        username: 'postgres',
      },
      testQueries: [
        {
          name: 'test-user-query',
          sql: 'SELECT * FROM users WHERE tenant_id = ?',
        },
      ],
      validationRules: {
        minRLSCoverage: 80,
        minCLSCoverage: 80,
      },
      testLogic: {
        skipDisabledPolicies: true,
        validateCrossTenant: true,
      },
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };

    // Default Network Policy Configuration
    const defaultNetworkPolicy: NetworkPolicyConfigurationEntity = {
      id: uuidv4(),
      name: 'Default Network Segmentation',
      type: 'network-policy',
      description: 'Default configuration for network policy testing',
      firewallRules: [
        {
          id: 'default-allow-frontend-backend',
          name: 'Allow Frontend to Backend',
          source: '10.0.1.0/24',
          destination: '10.0.2.0/24',
          protocol: 'tcp',
          port: 8080,
          action: 'allow',
          enabled: true,
        },
      ],
      networkSegments: [
        {
          id: 'default-frontend-segment',
          name: 'Frontend Segment',
          cidr: '10.0.1.0/24',
          services: ['frontend'],
          allowedConnections: ['backend'],
          deniedConnections: ['database'],
        },
      ],
      testLogic: {
        validateConnectivity: true,
        checkSegmentation: true,
      },
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };

    // Default DLP Configuration
    const defaultDLP: DLPConfigurationEntity = {
      id: uuidv4(),
      name: 'Default DLP Patterns',
      type: 'dlp',
      description: 'Default configuration for DLP testing',
      patterns: [
        {
          name: 'SSN Pattern',
          pattern: '\\d{3}-\\d{2}-\\d{4}',
          type: 'ssn',
        },
        {
          name: 'Credit Card Pattern',
          pattern: '\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}',
          type: 'credit-card',
        },
      ],
      bulkExportLimits: {
        csv: 10000,
        json: 10000,
        excel: 10000,
        api: 1000,
      },
      testLogic: {
        validateAPIResponses: true,
        checkBulkExports: true,
      },
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };

    // Default API Gateway Configuration
    const defaultAPIGateway: APIGatewayConfigurationEntity = {
      id: uuidv4(),
      name: 'Default API Gateway',
      type: 'api-gateway',
      description: 'Default configuration for API gateway testing',
      gatewayPolicies: [
        {
          id: 'default-api-policy',
          name: 'Default API Policy',
          endpoint: '/api/*',
          method: 'GET',
          rules: [],
        },
      ],
      rateLimitConfig: {
        defaultLimit: 100,
        defaultTimeWindow: 60,
        perEndpointLimits: {},
      },
      serviceAuthConfig: {
        methods: ['api-key', 'mtls'],
        requiredForEndpoints: [],
      },
      enabled: true,
      createdAt: now,
      updatedAt: now,
    };

    this.configurations = [
      defaultRLSCLS,
      defaultNetworkPolicy,
      defaultDLP,
      defaultAPIGateway,
    ];
    
    this.logger.log('Initialized default test configurations');
  }

  private async saveConfigurations(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      await fs.writeFile(this.configsFile, JSON.stringify(this.configurations, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving test configurations:', error);
      throw error;
    }
  }

  async findAll(type?: TestConfigurationType): Promise<TestConfigurationEntity[]> {
    try {
      await this.loadConfigurations();
      if (type) {
        return this.configurations.filter(c => c.type === type);
      }
      return this.configurations;
    } catch (error) {
      this.logger.error('Error in findAll:', error);
      throw error;
    }
  }

  async findOne(id: string): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const config = this.configurations.find(c => c.id === id);
    if (!config) {
      throw new NotFoundException(`Test configuration with ID ${id} not found`);
    }
    return config;
  }

  async create(dto: CreateTestConfigurationDto): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();

    // Check for duplicate name
    const existing = this.configurations.find(c => c.name === dto.name && c.type === dto.type);
    if (existing) {
      throw new BadRequestException(`Configuration with name "${dto.name}" and type "${dto.type}" already exists`);
    }

    const now = new Date();
    let newConfig: TestConfigurationEntity;

    switch (dto.type) {
      case 'rls-cls': {
        const rlsDto = dto as CreateRLSCLSConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: rlsDto.name,
          type: 'rls-cls',
          description: rlsDto.description,
          tags: rlsDto.tags || [],
          database: rlsDto.database,
          testQueries: rlsDto.testQueries,
          validationRules: rlsDto.validationRules,
          testLogic: rlsDto.testLogic,
          enabled: rlsDto.enabled !== undefined ? rlsDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as RLSCLSConfigurationEntity;
        break;
      }
      case 'network-policy': {
        const npDto = dto as CreateNetworkPolicyConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: npDto.name,
          type: 'network-policy',
          description: npDto.description,
          tags: npDto.tags || [],
          firewallRules: npDto.firewallRules,
          networkSegments: npDto.networkSegments,
          serviceMeshConfig: npDto.serviceMeshConfig,
          testLogic: npDto.testLogic,
          enabled: npDto.enabled !== undefined ? npDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as NetworkPolicyConfigurationEntity;
        break;
      }
      case 'dlp': {
        const dlpDto = dto as CreateDLPConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: dlpDto.name,
          type: 'dlp',
          description: dlpDto.description,
          tags: dlpDto.tags || [],
          patterns: dlpDto.patterns,
          bulkExportLimits: dlpDto.bulkExportLimits,
          piiDetectionRules: dlpDto.piiDetectionRules,
          testLogic: dlpDto.testLogic,
          enabled: dlpDto.enabled !== undefined ? dlpDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as DLPConfigurationEntity;
        break;
      }
      case 'api-gateway': {
        const agDto = dto as CreateAPIGatewayConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: agDto.name,
          type: 'api-gateway',
          description: agDto.description,
          tags: agDto.tags || [],
          rateLimitConfig: agDto.rateLimitConfig,
          serviceAuthConfig: agDto.serviceAuthConfig,
          gatewayPolicies: agDto.gatewayPolicies,
          testLogic: agDto.testLogic,
          enabled: agDto.enabled !== undefined ? agDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as APIGatewayConfigurationEntity;
        break;
      }
      case 'distributed-systems': {
        const dsDto = dto as CreateDistributedSystemsConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: dsDto.name,
          type: 'distributed-systems',
          description: dsDto.description,
          tags: dsDto.tags || [],
          regions: dsDto.regions,
          policySync: dsDto.policySync,
          coordination: dsDto.coordination,
          testLogic: dsDto.testLogic,
          enabled: dsDto.enabled !== undefined ? dsDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as DistributedSystemsConfigurationEntity;
        break;
      }
      case 'api-security': {
        const apiDto = dto as CreateAPISecurityConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: apiDto.name,
          type: 'api-security',
          description: apiDto.description,
          tags: apiDto.tags || [],
          baseUrl: apiDto.baseUrl,
          authentication: apiDto.authentication,
          rateLimitConfig: apiDto.rateLimitConfig,
          headers: apiDto.headers,
          timeout: apiDto.timeout,
          endpoints: apiDto.endpoints,
          testLogic: apiDto.testLogic,
          enabled: apiDto.enabled !== undefined ? apiDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as APISecurityConfigurationEntity;
        break;
      }
      case 'data-pipeline': {
        const pipelineDto = dto as CreateDataPipelineConfigurationDto;
        newConfig = {
          id: uuidv4(),
          name: pipelineDto.name,
          type: 'data-pipeline',
          description: pipelineDto.description,
          tags: pipelineDto.tags || [],
          pipelineType: pipelineDto.pipelineType,
          connection: pipelineDto.connection,
          dataSource: pipelineDto.dataSource,
          dataDestination: pipelineDto.dataDestination,
          testLogic: pipelineDto.testLogic,
          enabled: pipelineDto.enabled !== undefined ? pipelineDto.enabled : true,
          createdAt: now,
          updatedAt: now,
        } as DataPipelineConfigurationEntity;
        break;
      }
      default:
        throw new BadRequestException(`Unknown configuration type: ${(dto as any).type}`);
    }

    this.configurations.push(newConfig);
    await this.saveConfigurations();
    this.logger.log(`Created test configuration: ${newConfig.id} (${newConfig.type})`);
    return newConfig;
  }

  async update(id: string, dto: Partial<CreateTestConfigurationDto>): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const index = this.configurations.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test configuration with ID ${id} not found`);
    }

    const existing = this.configurations[index];
    
    // Check for duplicate name if name is being changed
    if (dto.name && dto.name !== existing.name) {
      const duplicate = this.configurations.find(
        c => c.name === dto.name && c.type === existing.type && c.id !== id
      );
      if (duplicate) {
        throw new BadRequestException(`Configuration with name "${dto.name}" and type "${existing.type}" already exists`);
      }
    }

    const updated = {
      ...existing,
      ...dto,
      id: existing.id, // Don't allow ID changes
      type: existing.type, // Don't allow type changes
      updatedAt: new Date(),
    } as TestConfigurationEntity;

    this.configurations[index] = updated;
    await this.saveConfigurations();
    this.logger.log(`Updated test configuration: ${id}`);
    return updated;
  }

  async delete(id: string): Promise<void> {
    await this.loadConfigurations();
    const index = this.configurations.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test configuration with ID ${id} not found`);
    }

    this.configurations.splice(index, 1);
    await this.saveConfigurations();
    this.logger.log(`Deleted test configuration: ${id}`);
  }

  async enable(id: string): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const config = await this.findOne(id);
    config.enabled = true;
    config.updatedAt = new Date();
    await this.saveConfigurations();
    this.logger.log(`Enabled test configuration: ${id}`);
    return config;
  }

  async disable(id: string): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const config = await this.findOne(id);
    config.enabled = false;
    config.updatedAt = new Date();
    await this.saveConfigurations();
    this.logger.log(`Disabled test configuration: ${id}`);
    return config;
  }

  async duplicate(id: string, newName?: string): Promise<TestConfigurationEntity> {
    await this.loadConfigurations();
    const original = await this.findOne(id);
    
    const duplicated = {
      ...original,
      id: uuidv4(),
      name: newName || `${original.name} (Copy)`,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.configurations.push(duplicated);
    await this.saveConfigurations();
    this.logger.log(`Duplicated test configuration: ${id} -> ${duplicated.id}`);
    return duplicated;
  }

  /**
   * Test a configuration by executing the appropriate test based on configuration type.
   * 
   * @param id - Configuration ID to test
   * @param context - Optional context including applicationId, buildId, runId, commitSha, branch
   * @param saveResult - Optional flag to save test result to storage (requires applicationId in context)
   * @returns Test result object
   */
  async testConfiguration(
    id: string,
    context?: {
      applicationId?: string;
      buildId?: string;
      runId?: string;
      commitSha?: string;
      branch?: string;
    },
    saveResult?: boolean
  ): Promise<any> {
    await this.loadConfigurations();
    const config = await this.findOne(id);

    this.logger.log(`Testing configuration: ${id} (${config.type})${context?.applicationId ? ` for application ${context.applicationId}` : ''}`);

    const testStartTime = Date.now();
    try {
      let result: any;
      switch (config.type) {
        case 'rls-cls': {
          const rlsConfig = config as RLSCLSConfigurationEntity;
          // Run RLS coverage test as the primary test
          result = await this.rlsClsService.testRLSCoverage({ configId: id });
          break;
        }
        case 'network-policy': {
          const npConfig = config as NetworkPolicyConfigurationEntity;
          // Run firewall rules test as the primary test
          result = await this.networkPolicyService.testFirewallRules({ configId: id });
          break;
        }
        case 'dlp': {
          const dlpConfig = config as DLPConfigurationEntity;
          // Run exfiltration test as the primary test
          result = await this.dlpService.testExfiltration({ configId: id });
          break;
        }
        case 'api-gateway': {
          const agConfig = config as APIGatewayConfigurationEntity;
          // Run rate limiting test as the primary test
          result = await this.apiGatewayService.testRateLimiting({ configId: id });
          break;
        }
        case 'distributed-systems': {
          const dsConfig = config as DistributedSystemsConfigurationEntity;
          // Run a multi-region test as the primary test
          result = await this.distributedSystemsService.runTest({
            name: `Test: ${dsConfig.name}`,
            testType: 'multi-region',
            configId: id,
          });
          break;
        }
        case 'api-security': {
          const apiConfig = config as APISecurityConfigurationEntity;
          // Run API security test
          result = await this.apiSecurityService.runTest(id, context);
          break;
        }
        case 'data-pipeline': {
          const pipelineConfig = config as DataPipelineConfigurationEntity;
          // Run data pipeline test
          result = await this.dataPipelineService.runTest(id, context);
          break;
        }
        default:
          throw new BadRequestException(`Unknown configuration type: ${(config as any).type}`);
      }

      // Add context metadata to result if provided
      if (context) {
        result = {
          ...result,
          applicationId: context.applicationId,
          buildId: context.buildId,
          runId: context.runId,
          commitSha: context.commitSha,
          branch: context.branch,
          testConfigurationId: id,
          testConfigurationName: config.name,
          timestamp: new Date(),
        };
      }

      // Save result if requested and applicationId is provided
      if (saveResult && context?.applicationId) {
        try {
          const testPassed = result.passed !== false;
          const testStatus: TestResultStatus = testPassed ? 'passed' : 'failed';
          const testDuration = Date.now() - testStartTime;

          // Get application name
          let applicationName = 'Unknown';
          try {
            const application = await this.applicationsService.findOne(context.applicationId);
            applicationName = application.name;
          } catch (err) {
            this.logger.warn(`Could not load application ${context.applicationId} for result storage: ${err}`);
          }

          await this.testResultsService.saveResult({
            applicationId: context.applicationId,
            applicationName,
            testConfigurationId: id,
            testConfigurationName: config.name,
            testConfigurationType: config.type,
            status: testStatus,
            passed: testPassed,
            buildId: context.buildId,
            runId: context.runId,
            commitSha: context.commitSha,
            branch: context.branch,
            timestamp: new Date(),
            duration: testDuration,
            result: result,
            error: result.error ? {
              message: result.error.message || result.error,
              type: result.error.type || 'Error',
              details: result.error.details || result.error,
            } : undefined,
            metadata: {
              buildId: context.buildId,
              runId: context.runId,
              commitSha: context.commitSha,
              branch: context.branch,
            },
          });

          this.logger.log(`Saved test result for configuration ${id} and application ${context.applicationId}`);
        } catch (storageError: any) {
          // Log but don't fail the test execution if storage fails
          this.logger.warn(`Failed to save test result for configuration ${id}: ${storageError.message}`);
        }
      }

      return result;
    } catch (error: any) {
      this.logger.error(`Error testing configuration ${id}: ${error.message}`, error.stack);
      throw error;
    }
  }

  async findApplicationsUsingConfig(configId: string): Promise<any[]> {
    return this.applicationsService.findApplicationsUsingConfig(configId);
  }
}

