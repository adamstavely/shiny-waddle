import { Injectable, NotFoundException, Logger, Inject, forwardRef } from '@nestjs/common';
import {
  CreateAPISecurityConfigDto,
  CreateAPIEndpointDto,
  CreateAPISecurityTestDto,
  UpdateAPISecurityConfigDto,
} from './dto/create-api-security.dto';
import {
  APISecurityTestConfigEntity,
  APIEndpointEntity,
  APISecurityTestResultEntity,
  APITestType,
} from './entities/api-security.entity';
import { APISecurityTester, APISecurityTestConfig } from '../../../services/api-security-tester';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { APISecurityConfigurationEntity } from '../test-configurations/entities/test-configuration.entity';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ApiSecurityService {
  private readonly logger = new Logger(ApiSecurityService.name);
  private readonly configsFile = path.join(process.cwd(), '..', '..', 'data', 'api-security-configs.json');
  private readonly endpointsFile = path.join(process.cwd(), '..', '..', 'data', 'api-security-endpoints.json');
  private readonly resultsFile = path.join(process.cwd(), '..', '..', 'data', 'api-security-results.json');

  private configs: APISecurityTestConfigEntity[] = [];
  private endpoints: APIEndpointEntity[] = [];
  private results: APISecurityTestResultEntity[] = [];

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly testConfigurationsService?: TestConfigurationsService,
  ) {
    this.loadData().catch(err => {
      console.error('Error loading API security data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    await Promise.all([
      this.loadConfigs(),
      this.loadEndpoints(),
      this.loadResults(),
    ]);
  }

  private async loadConfigs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.configsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.configs = (Array.isArray(parsed) ? parsed : []).map((c: any) => ({
          ...c,
          createdAt: new Date(c.createdAt),
          updatedAt: new Date(c.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.configs = [];
          await this.saveConfigs();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading API security configs:', error);
      this.configs = [];
    }
  }

  private async loadEndpoints(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.endpointsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.endpointsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.endpoints = (Array.isArray(parsed) ? parsed : []).map((e: any) => ({
          ...e,
          createdAt: new Date(e.createdAt),
          updatedAt: new Date(e.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.endpoints = [];
          await this.saveEndpoints();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading API endpoints:', error);
      this.endpoints = [];
    }
  }

  private async loadResults(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.resultsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.results = (Array.isArray(parsed) ? parsed : []).map((r: any) => ({
          ...r,
          timestamp: new Date(r.timestamp),
          createdAt: new Date(r.createdAt),
          rateLimitInfo: r.rateLimitInfo ? {
            ...r.rateLimitInfo,
            resetTime: r.rateLimitInfo.resetTime ? new Date(r.rateLimitInfo.resetTime) : undefined,
          } : undefined,
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.results = [];
          await this.saveResults();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading API security results:', error);
      this.results = [];
    }
  }

  private async saveConfigs() {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      await fs.writeFile(this.configsFile, JSON.stringify(this.configs, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving API security configs:', error);
      throw error;
    }
  }

  private async saveEndpoints() {
    try {
      await fs.mkdir(path.dirname(this.endpointsFile), { recursive: true });
      await fs.writeFile(this.endpointsFile, JSON.stringify(this.endpoints, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving API endpoints:', error);
      throw error;
    }
  }

  private async saveResults() {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      await fs.writeFile(this.resultsFile, JSON.stringify(this.results, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving API security results:', error);
      throw error;
    }
  }

  // Configs
  async createConfig(dto: CreateAPISecurityConfigDto): Promise<APISecurityTestConfigEntity> {
    const config: APISecurityTestConfigEntity = {
      id: uuidv4(),
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.configs.push(config);
    await this.saveConfigs();

    return config;
  }

  async findAllConfigs(): Promise<APISecurityTestConfigEntity[]> {
    return this.configs;
  }

  async findOneConfig(id: string): Promise<APISecurityTestConfigEntity> {
    const config = this.configs.find(c => c.id === id);
    if (!config) {
      throw new NotFoundException(`API security config with ID "${id}" not found`);
    }
    return config;
  }

  async updateConfig(id: string, dto: UpdateAPISecurityConfigDto): Promise<APISecurityTestConfigEntity> {
    const index = this.configs.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`API security config with ID "${id}" not found`);
    }

    this.configs[index] = {
      ...this.configs[index],
      ...dto,
      updatedAt: new Date(),
    };

    await this.saveConfigs();

    return this.configs[index];
  }

  async removeConfig(id: string): Promise<void> {
    const index = this.configs.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`API security config with ID "${id}" not found`);
    }

    this.configs.splice(index, 1);
    await this.saveConfigs();

    // Also remove associated endpoints
    this.endpoints = this.endpoints.filter(e => e.configId !== id);
    await this.saveEndpoints();
  }

  // Endpoints
  async createEndpoint(dto: CreateAPIEndpointDto): Promise<APIEndpointEntity> {
    const endpoint: APIEndpointEntity = {
      id: uuidv4(),
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.endpoints.push(endpoint);
    await this.saveEndpoints();

    return endpoint;
  }

  async findAllEndpoints(configId?: string): Promise<APIEndpointEntity[]> {
    if (configId) {
      return this.endpoints.filter(e => e.configId === configId);
    }
    return this.endpoints;
  }

  async findOneEndpoint(id: string): Promise<APIEndpointEntity> {
    const endpoint = this.endpoints.find(e => e.id === id);
    if (!endpoint) {
      throw new NotFoundException(`API endpoint with ID "${id}" not found`);
    }
    return endpoint;
  }

  async removeEndpoint(id: string): Promise<void> {
    const index = this.endpoints.findIndex(e => e.id === id);
    if (index === -1) {
      throw new NotFoundException(`API endpoint with ID "${id}" not found`);
    }

    this.endpoints.splice(index, 1);
    await this.saveEndpoints();
  }

  // Test Results
  async createTestResult(dto: CreateAPISecurityTestDto): Promise<APISecurityTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const endpoint = dto.endpointId 
      ? await this.findOneEndpoint(dto.endpointId)
      : null;

    if (!endpoint && !dto.endpoint) {
      throw new NotFoundException('Either endpointId or endpoint must be provided');
    }

    const endpointData = endpoint || {
      id: '',
      configId: dto.configId,
      name: dto.testName,
      endpoint: dto.endpoint!,
      method: dto.method,
      apiType: dto.testType,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await this.executeAPISecurityTest(
      config,
      endpointData,
      dto.testType
    );

    this.results.push(result);
    await this.saveResults();

    return result;
  }

  /**
   * Run API Security test for test configuration system
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
    // First try to get config from test-configurations system
    let config: APISecurityTestConfigEntity | null = null;
    let endpoints: APIEndpointEntity[] = [];
    let selectedTestSuites: string[] | undefined = undefined;
    
    if (this.testConfigurationsService) {
      try {
        const testConfig = await this.testConfigurationsService.findOne(configId);
        if (testConfig.type === 'api-security') {
          const apiConfig = testConfig as APISecurityConfigurationEntity;
          // Convert test-configuration entity to API security config entity
          config = {
            id: apiConfig.id,
            name: apiConfig.name,
            baseUrl: apiConfig.baseUrl,
            authentication: apiConfig.authentication,
            rateLimitConfig: apiConfig.rateLimitConfig,
            headers: apiConfig.headers,
            timeout: apiConfig.timeout,
            createdAt: apiConfig.createdAt,
            updatedAt: apiConfig.updatedAt,
          };
          // Get selected test suites from testLogic
          selectedTestSuites = apiConfig.testLogic?.selectedTestSuites;
          // Convert endpoints if they exist
          if (apiConfig.endpoints) {
            endpoints = apiConfig.endpoints.map(ep => ({
              id: ep.id || uuidv4(),
              configId: apiConfig.id,
              name: ep.name,
              endpoint: ep.endpoint,
              method: ep.method as any,
              apiType: ep.apiType as any,
              expectedStatus: ep.expectedStatus,
              expectedAuthRequired: ep.expectedAuthRequired,
              expectedRateLimit: ep.expectedRateLimit,
              body: ep.body,
              headers: ep.headers,
              createdAt: new Date(),
              updatedAt: new Date(),
            }));
          }
        }
      } catch (error) {
        // Config not found in test-configurations, try standalone storage
        this.logger.debug(`Config ${configId} not found in test-configurations, trying standalone storage`);
      }
    }
    
    // Fallback to standalone storage if not found in test-configurations
    if (!config) {
      config = await this.findOneConfig(configId);
      endpoints = await this.findAllEndpoints(configId);
    }

    if (endpoints.length === 0) {
      throw new NotFoundException(`No endpoints found for API security config "${configId}"`);
    }

    // Run tests for all endpoints or just the first one
    const results = [];
    for (const endpoint of endpoints) {
      try {
        const result = await this.executeAPISecurityTest(config, endpoint, endpoint.apiType, selectedTestSuites);
        results.push(result);
      } catch (error: any) {
        this.logger.error(`Error running test for endpoint ${endpoint.id}: ${error.message}`);
        results.push({
          id: uuidv4(),
          configId: config.id,
          endpointId: endpoint.id,
          testName: endpoint.name,
          endpoint: endpoint.endpoint,
          method: endpoint.method,
          testType: endpoint.apiType,
          status: 'failed' as const,
          error: error.message,
          timestamp: new Date(),
          createdAt: new Date(),
        });
      }
    }

    // Aggregate results
    const passed = results.every(r => r.status === 'passed');
    const overallResult = {
      passed,
      testType: 'api-security',
      testName: `API Security Test: ${config.name}`,
      timestamp: new Date(),
      details: {
        configId: config.id,
        configName: config.name,
        endpointCount: endpoints.length,
        results,
      },
      ...context,
    };

    return overallResult;
  }

  /**
   * Execute API Security test using APISecurityTester
   */
  private async executeAPISecurityTest(
    config: APISecurityTestConfigEntity,
    endpoint: APIEndpointEntity,
    testType: APITestType,
    selectedTestSuites?: string[]
  ): Promise<APISecurityTestResultEntity> {
    const testerConfig: APISecurityTestConfig = {
      baseUrl: config.baseUrl,
      authentication: config.authentication ? {
        type: config.authentication.type as any,
        credentials: config.authentication.credentials,
      } : undefined,
      rateLimitConfig: config.rateLimitConfig,
      headers: config.headers,
      timeout: config.timeout || 5000,
    };

    const tester = new APISecurityTester(testerConfig);

    const test: any = {
      name: endpoint.name,
      endpoint: endpoint.endpoint,
      method: endpoint.method as any,
      expectedStatus: endpoint.expectedStatus,
      expectedAuthRequired: endpoint.expectedAuthRequired,
      body: endpoint.body,
      headers: endpoint.headers,
    };

    let result: any;

    try {
      // If selectedTestSuites is provided and not empty, use test suites
      if (selectedTestSuites && selectedTestSuites.length > 0) {
        const allSuiteResults: any[] = [];
        
        // Run each selected test suite
        for (const suiteName of selectedTestSuites) {
          try {
            const suiteResults = await tester.runTestSuite(
              suiteName,
              endpoint.endpoint,
              endpoint.method as any,
              test
            );
            allSuiteResults.push(...suiteResults);
          } catch (error: any) {
            this.logger.warn(`Error running test suite ${suiteName}: ${error.message}`);
            // Create error result for failed suite
            allSuiteResults.push({
              testName: `${suiteName} Suite Error`,
              endpoint: endpoint.endpoint,
              method: endpoint.method,
              testType: 'api-security',
              passed: false,
              timestamp: new Date(),
              error: error.message,
              details: { suite: suiteName, error: error.message },
            });
          }
        }

        // Aggregate suite results into a single result
        const passed = allSuiteResults.every(r => r.passed !== false);
        const aggregatedResult = {
          testName: endpoint.name,
          endpoint: endpoint.endpoint,
          method: endpoint.method,
          testType: testType,
          passed,
          timestamp: new Date(),
          details: {
            suiteResults: allSuiteResults,
            suitesRun: selectedTestSuites,
            totalSuites: selectedTestSuites.length,
            passedSuites: allSuiteResults.filter(r => r.passed !== false).length,
          },
          // Aggregate common fields from first result if available
          statusCode: allSuiteResults[0]?.statusCode,
          responseTime: allSuiteResults[0]?.responseTime,
          rateLimitInfo: allSuiteResults[0]?.rateLimitInfo,
          authenticationResult: allSuiteResults[0]?.authenticationResult,
          authorizationResult: allSuiteResults[0]?.authorizationResult,
          securityIssues: allSuiteResults.flatMap(r => r.securityIssues || []),
        };

        result = aggregatedResult;
      } else {
        // Fall back to current behavior (switch on testType)
        switch (testType) {
          case APITestType.REST:
            result = await tester.testRESTAPI(test);
            break;

          case APITestType.AUTHENTICATION:
            result = await tester.testAuthentication(test);
            break;

          case APITestType.AUTHORIZATION:
            const authzResults = await tester.testAuthorization([test]);
            result = authzResults[0] || authzResults;
            break;

          case APITestType.RATE_LIMITING:
            result = await tester.testRateLimiting(endpoint.endpoint, endpoint.method as any);
            break;

          case APITestType.GRAPHQL:
            // For GraphQL, we'd need a query - using REST as fallback
            result = await tester.testRESTAPI(test);
            break;

          default:
            // Default to REST API test
            result = await tester.testRESTAPI(test);
        }
      }

      // Convert APISecurityTester result to APISecurityTestResultEntity
      const resultEntity: APISecurityTestResultEntity = {
        id: uuidv4(),
        configId: config.id,
        endpointId: endpoint.id,
        testName: endpoint.name,
        endpoint: endpoint.endpoint,
        method: endpoint.method,
        testType: testType,
        status: result.passed ? 'passed' : 'failed',
        statusCode: result.statusCode,
        responseTime: result.responseTime,
        rateLimitInfo: result.rateLimitInfo,
        authenticationResult: result.authenticationResult,
        authorizationResult: result.authorizationResult,
        securityIssues: result.securityIssues,
        details: result.details,
        error: result.error,
        timestamp: new Date(),
        createdAt: new Date(),
      };

      return resultEntity;
    } catch (error: any) {
      this.logger.error(`Error executing API security test: ${error.message}`, error.stack);
      throw error;
    }
  }

  async findAllResults(
    configId?: string,
    endpointId?: string,
    testType?: string,
    status?: string,
  ): Promise<APISecurityTestResultEntity[]> {
    let filtered = [...this.results];

    if (configId) {
      filtered = filtered.filter(r => r.configId === configId);
    }
    if (endpointId) {
      filtered = filtered.filter(r => r.endpointId === endpointId);
    }
    if (testType) {
      filtered = filtered.filter(r => r.testType === testType);
    }
    if (status) {
      filtered = filtered.filter(r => r.status === status);
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async findOneResult(id: string): Promise<APISecurityTestResultEntity> {
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`API security test result with ID "${id}" not found`);
    }
    return result;
  }
}

