import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import {
  CreateSalesforceExperienceCloudConfigDto,
  UpdateSalesforceExperienceCloudConfigDto,
  RunGuestAccessTestDto,
  RunAuthenticatedAccessTestDto,
  RunGraphQLTestDto,
  RunSelfRegistrationTestDto,
  RunRecordListTestDto,
  RunHomeURLTestDto,
  RunObjectAccessTestDto,
  RunFullAuditDto,
} from './dto/salesforce-experience-cloud.dto';
import {
  SalesforceExperienceCloudConfigEntity,
  SalesforceExperienceCloudTestResultEntity,
} from './entities/salesforce-experience-cloud.entity';
import {
  SalesforceExperienceCloudTester,
  SalesforceExperienceCloudConfig,
  SalesforceExperienceCloudTestResult,
} from '../../../heimdall-framework/services/salesforce-experience-cloud-tester';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class SalesforceExperienceCloudService {
  private readonly logger = new Logger(SalesforceExperienceCloudService.name);
  private readonly configsFile = path.join(process.cwd(), '..', 'data', 'salesforce-experience-cloud-configs.json');
  private readonly resultsFile = path.join(process.cwd(), '..', 'data', 'salesforce-experience-cloud-results.json');

  private configs: SalesforceExperienceCloudConfigEntity[] = [];
  private results: SalesforceExperienceCloudTestResultEntity[] = [];

  constructor() {
    this.loadData().catch(err => {
      this.logger.error('Error loading Salesforce Experience Cloud data on startup', err instanceof Error ? err.stack : String(err));
    });
  }

  private async loadData(): Promise<void> {
    await Promise.all([
      this.loadConfigs(),
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
      this.logger.error('Error loading Salesforce Experience Cloud configs', error instanceof Error ? error.stack : String(error));
      this.configs = [];
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
      this.logger.error('Error loading Salesforce Experience Cloud results', error instanceof Error ? error.stack : String(error));
      this.results = [];
    }
  }

  private async saveConfigs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      await fs.writeFile(this.configsFile, JSON.stringify(this.configs, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving Salesforce Experience Cloud configs', error instanceof Error ? error.stack : String(error));
      throw error;
    }
  }

  private async saveResults(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      await fs.writeFile(this.resultsFile, JSON.stringify(this.results, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving Salesforce Experience Cloud results', error instanceof Error ? error.stack : String(error));
      throw error;
    }
  }

  private mapConfigToTesterConfig(config: SalesforceExperienceCloudConfigEntity): SalesforceExperienceCloudConfig {
    return {
      url: config.url,
      cookies: config.cookies,
      outputDir: config.outputDir,
      objectList: config.objectList,
      app: config.app,
      aura: config.aura,
      context: config.context,
      token: config.token,
      noGraphQL: config.noGraphQL,
      proxy: config.proxy,
      insecure: config.insecure,
      auraRequestFile: config.auraRequestFile,
      auraInspectorPath: config.auraInspectorPath,
      timeout: config.timeout,
      pythonPath: config.pythonPath,
    };
  }

  private mapTestResultToEntity(
    configId: string,
    testType: string,
    testResult: SalesforceExperienceCloudTestResult,
  ): SalesforceExperienceCloudTestResultEntity {
    const details = testResult.details || {};
    const findings = details.findings || [];
    const summary = details.summary || {};

    return {
      id: uuidv4(),
      configId,
      testName: testResult.testName,
      testType,
      status: testResult.passed ? 'passed' : (testResult.error ? 'failed' : 'warning'),
      findings,
      accessibleRecords: details.accessibleRecords,
      recordCount: details.recordCount,
      urls: details.urls,
      objects: details.objects,
      summary: {
        totalFindings: summary.totalFindings || findings.length,
        criticalCount: summary.criticalCount || findings.filter((f: any) => f.severity === 'critical').length,
        highCount: summary.highCount || findings.filter((f: any) => f.severity === 'high').length,
        mediumCount: summary.mediumCount || findings.filter((f: any) => f.severity === 'medium').length,
        lowCount: summary.lowCount || findings.filter((f: any) => f.severity === 'low').length,
        infoCount: summary.infoCount || findings.filter((f: any) => f.severity === 'info').length,
      },
      details: testResult.details,
      error: testResult.error,
      timestamp: testResult.timestamp,
      createdAt: new Date(),
    };
  }

  // Configuration Management
  async createConfig(dto: CreateSalesforceExperienceCloudConfigDto): Promise<SalesforceExperienceCloudConfigEntity> {
    const config: SalesforceExperienceCloudConfigEntity = {
      id: uuidv4(),
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.configs.push(config);
    await this.saveConfigs();

    return config;
  }

  async findAllConfigs(): Promise<SalesforceExperienceCloudConfigEntity[]> {
    return this.configs;
  }

  async findOneConfig(id: string): Promise<SalesforceExperienceCloudConfigEntity> {
    const config = this.configs.find(c => c.id === id);
    if (!config) {
      throw new NotFoundException(`Salesforce Experience Cloud config with ID "${id}" not found`);
    }
    return config;
  }

  async updateConfig(id: string, dto: UpdateSalesforceExperienceCloudConfigDto): Promise<SalesforceExperienceCloudConfigEntity> {
    const index = this.configs.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`Salesforce Experience Cloud config with ID "${id}" not found`);
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
      throw new NotFoundException(`Salesforce Experience Cloud config with ID "${id}" not found`);
    }

    this.configs.splice(index, 1);
    await this.saveConfigs();

    // Optionally remove associated results
    // this.results = this.results.filter(r => r.configId !== id);
    // await this.saveResults();
  }

  // Test Execution
  async runGuestAccessTest(dto: RunGuestAccessTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    
    // Override cookies if provided
    if (dto.cookies !== undefined) {
      testerConfig.cookies = dto.cookies;
    }

    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testGuestAccess();
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'guest-access', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runAuthenticatedAccessTest(dto: RunAuthenticatedAccessTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    
    // Override cookies if provided
    if (dto.cookies !== undefined) {
      testerConfig.cookies = dto.cookies;
    }

    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testAuthenticatedAccess();
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'authenticated-access', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runGraphQLTest(dto: RunGraphQLTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testGraphQLCapability();
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'graphql', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runSelfRegistrationTest(dto: RunSelfRegistrationTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testSelfRegistration();
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'self-registration', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runRecordListTest(dto: RunRecordListTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testRecordListComponents();
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'record-lists', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runHomeURLTest(dto: RunHomeURLTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testHomeURLs();
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'home-urls', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runObjectAccessTest(dto: RunObjectAccessTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    if (!dto.objects || dto.objects.length === 0) {
      throw new BadRequestException('objects array is required and must not be empty');
    }

    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResult = await tester.testObjectAccess(dto.objects);
    
    const resultEntity = this.mapTestResultToEntity(config.id, 'object-access', testResult);
    this.results.push(resultEntity);
    await this.saveResults();

    return resultEntity;
  }

  async runFullAudit(dto: RunFullAuditDto): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.mapConfigToTesterConfig(config);
    const tester = new SalesforceExperienceCloudTester(testerConfig);
    const testResults = await tester.runFullAudit();
    
    const resultEntities = testResults.map((testResult, index) => {
      // Full audit returns TestResult[], we need to map them appropriately
      const testType = testResult.testName.toLowerCase().includes('guest') ? 'guest-access' :
                      testResult.testName.toLowerCase().includes('authenticated') ? 'authenticated-access' :
                      testResult.testName.toLowerCase().includes('graphql') ? 'graphql' :
                      testResult.testName.toLowerCase().includes('registration') ? 'self-registration' :
                      testResult.testName.toLowerCase().includes('record') ? 'record-lists' :
                      testResult.testName.toLowerCase().includes('home') ? 'home-urls' :
                      'full-audit';
      
      return this.mapTestResultToEntity(config.id, testType, testResult);
    });

    this.results.push(...resultEntities);
    await this.saveResults();

    return resultEntities;
  }

  // Results Management
  async findAllResults(configId?: string): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    if (configId) {
      return this.results.filter(r => r.configId === configId);
    }
    return this.results;
  }

  async findOneResult(id: string): Promise<SalesforceExperienceCloudTestResultEntity> {
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`Salesforce Experience Cloud test result with ID "${id}" not found`);
    }
    return result;
  }

  async getSummary(): Promise<{ configs: number; results: number }> {
    return {
      configs: this.configs.length,
      results: this.results.length,
    };
  }
}
