import { Injectable, NotFoundException, Logger } from '@nestjs/common';
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
  SalesforceExperienceCloudTestType,
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
      console.error('Error loading Salesforce Experience Cloud data on startup:', err);
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
      console.error('Error loading Salesforce Experience Cloud configs:', error);
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
      console.error('Error loading Salesforce Experience Cloud results:', error);
      this.results = [];
    }
  }

  private async saveConfigs() {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      await fs.writeFile(this.configsFile, JSON.stringify(this.configs, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving Salesforce Experience Cloud configs:', error);
      throw error;
    }
  }

  private async saveResults() {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      await fs.writeFile(this.resultsFile, JSON.stringify(this.results, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving Salesforce Experience Cloud results:', error);
      throw error;
    }
  }

  // Configs
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

    // Also remove associated results
    this.results = this.results.filter(r => r.configId !== id);
    await this.saveResults();
  }

  // Tests
  private configToTesterConfig(config: SalesforceExperienceCloudConfigEntity): SalesforceExperienceCloudConfig {
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

  private testResultToEntity(
    configId: string,
    testType: SalesforceExperienceCloudTestType,
    testResult: SalesforceExperienceCloudTestResult
  ): SalesforceExperienceCloudTestResultEntity {
    const status: 'passed' | 'failed' | 'warning' = testResult.passed
      ? 'passed'
      : testResult.details?.findings?.some((f: any) => f.severity === 'high' || f.severity === 'critical')
      ? 'failed'
      : 'warning';

    return {
      id: uuidv4(),
      configId,
      testName: testResult.testName,
      testType,
      status,
      findings: testResult.details?.findings,
      accessibleRecords: testResult.details?.accessibleRecords,
      recordCount: testResult.details?.recordCount,
      urls: testResult.details?.urls,
      objects: testResult.details?.objects,
      summary: testResult.details?.summary,
      details: testResult.details,
      error: testResult.error,
      timestamp: testResult.timestamp,
      createdAt: new Date(),
    };
  }

  async runGuestAccessTest(dto: RunGuestAccessTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running guest access test for config ${dto.configId}`);
    const result = await tester.testGuestAccess();

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.GUEST_ACCESS, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runAuthenticatedAccessTest(dto: RunAuthenticatedAccessTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const testerConfig = this.configToTesterConfig(config);
    
    // Override cookies if provided
    if (dto.cookies) {
      testerConfig.cookies = dto.cookies;
    }

    const tester = new SalesforceExperienceCloudTester(testerConfig);

    this.logger.log(`Running authenticated access test for config ${dto.configId}`);
    const result = await tester.testAuthenticatedAccess();

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.AUTHENTICATED_ACCESS, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runGraphQLTest(dto: RunGraphQLTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running GraphQL test for config ${dto.configId}`);
    const result = await tester.testGraphQLCapability();

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.GRAPHQL, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runSelfRegistrationTest(dto: RunSelfRegistrationTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running self-registration test for config ${dto.configId}`);
    const result = await tester.testSelfRegistration();

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.SELF_REGISTRATION, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runRecordListTest(dto: RunRecordListTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running record list test for config ${dto.configId}`);
    const result = await tester.testRecordListComponents();

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.RECORD_LISTS, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runHomeURLTest(dto: RunHomeURLTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running home URL test for config ${dto.configId}`);
    const result = await tester.testHomeURLs();

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.HOME_URLS, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runObjectAccessTest(dto: RunObjectAccessTestDto): Promise<SalesforceExperienceCloudTestResultEntity> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running object access test for config ${dto.configId} with objects: ${dto.objects.join(', ')}`);
    const result = await tester.testObjectAccess(dto.objects);

    const entity = this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.OBJECT_ACCESS, result);
    this.results.push(entity);
    await this.saveResults();

    return entity;
  }

  async runFullAudit(dto: RunFullAuditDto): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    const config = await this.findOneConfig(dto.configId);
    const tester = new SalesforceExperienceCloudTester(this.configToTesterConfig(config));

    this.logger.log(`Running full audit for config ${dto.configId}`);
    const results = await tester.runFullAudit();

    const entities = results.map(result =>
      this.testResultToEntity(dto.configId, SalesforceExperienceCloudTestType.FULL_AUDIT, result)
    );

    this.results.push(...entities);
    await this.saveResults();

    return entities;
  }

  // Results
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

  async removeResult(id: string): Promise<void> {
    const index = this.results.findIndex(r => r.id === id);
    if (index === -1) {
      throw new NotFoundException(`Salesforce Experience Cloud test result with ID "${id}" not found`);
    }

    this.results.splice(index, 1);
    await this.saveResults();
  }
}
