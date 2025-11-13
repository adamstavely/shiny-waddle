import { Injectable, NotFoundException, ConflictException, BadRequestException, Inject, forwardRef, Logger } from '@nestjs/common';
import { CreateApplicationDto, ApplicationType, ApplicationStatus } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { Application } from './entities/application.entity';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { TestResultsService } from '../test-results/test-results.service';
import { TestResultStatus } from '../test-results/entities/test-result.entity';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ApplicationsService {
  private readonly logger = new Logger(ApplicationsService.name);
  private readonly applicationsFile = path.join(process.cwd(), 'data', 'applications.json');
  private applications: Application[] = [];

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly testConfigurationsService: TestConfigurationsService,
    @Inject(forwardRef(() => TestResultsService))
    private readonly testResultsService: TestResultsService,
  ) {
    // Load applications asynchronously
    this.loadApplications().catch(err => {
      console.error('Error loading applications on startup:', err);
    });
  }

  private async loadApplications(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.applicationsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.applicationsFile, 'utf-8');
        if (!data || data.trim() === '') {
          // Empty file, start with empty array
          this.applications = [];
          await this.saveApplications();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Applications file does not contain an array, starting with empty array');
          this.applications = [];
          await this.saveApplications();
          return;
        }
        this.applications = parsed.map((app: any) => ({
          ...app,
          registeredAt: app.registeredAt ? new Date(app.registeredAt) : new Date(),
          lastTestAt: app.lastTestAt ? new Date(app.lastTestAt) : undefined,
          updatedAt: app.updatedAt ? new Date(app.updatedAt) : new Date(),
        }));
      } catch (readError: any) {
        // File doesn't exist or is invalid, start with empty array
        if (readError.code === 'ENOENT') {
          this.applications = [];
          await this.saveApplications();
        } else if (readError instanceof SyntaxError) {
          // JSON parsing error - file is corrupted
          this.logger.error('JSON parsing error in applications file, starting with empty array:', readError.message);
          this.applications = [];
          await this.saveApplications();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading applications:', error);
      // Start with empty array if there's an error
      this.applications = [];
    }
  }

  private async saveApplications() {
    try {
      await fs.mkdir(path.dirname(this.applicationsFile), { recursive: true });
      await fs.writeFile(
        this.applicationsFile,
        JSON.stringify(this.applications, null, 2),
        'utf-8',
      );
    } catch (error) {
      console.error('Error saving applications:', error);
      throw error;
    }
  }

  async create(createApplicationDto: CreateApplicationDto): Promise<Application> {
    // Check if application with this ID already exists
    const existing = this.applications.find(app => app.id === createApplicationDto.id);
    if (existing) {
      throw new ConflictException(`Application with ID "${createApplicationDto.id}" already exists`);
    }

    const application: Application = {
      id: createApplicationDto.id,
      name: createApplicationDto.name,
      type: createApplicationDto.type,
      status: createApplicationDto.status || ApplicationStatus.ACTIVE,
      baseUrl: createApplicationDto.baseUrl,
      team: createApplicationDto.team,
      description: createApplicationDto.description,
      config: createApplicationDto.config || {},
      registeredAt: new Date(),
      updatedAt: new Date(),
    };

    this.applications.push(application);
    await this.saveApplications();

    return application;
  }

  async findAll(): Promise<Application[]> {
    try {
      // Ensure data is loaded
      if (this.applications.length === 0) {
        await this.loadApplications();
      }
      return this.applications;
    } catch (error) {
      this.logger.error('Error in findAll:', error);
      throw error;
    }
  }

  async findOne(id: string): Promise<Application> {
    const application = this.applications.find(app => app.id === id);
    if (!application) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }
    return application;
  }

  async update(id: string, updateApplicationDto: UpdateApplicationDto): Promise<Application> {
    const index = this.applications.findIndex(app => app.id === id);
    if (index === -1) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }

    // Don't allow updating the ID
    const { id: _, ...updateData } = updateApplicationDto;

    this.applications[index] = {
      ...this.applications[index],
      ...updateData,
      updatedAt: new Date(),
    };

    await this.saveApplications();

    return this.applications[index];
  }

  async remove(id: string): Promise<void> {
    const index = this.applications.findIndex(app => app.id === id);
    if (index === -1) {
      throw new NotFoundException(`Application with ID "${id}" not found`);
    }

    this.applications.splice(index, 1);
    await this.saveApplications();
  }

  async updateLastTestAt(id: string, testDate: Date): Promise<Application> {
    const application = await this.findOne(id);
    application.lastTestAt = testDate;
    application.updatedAt = new Date();
    await this.saveApplications();
    return application;
  }

  async findByTeam(team: string): Promise<Application[]> {
    try {
      if (this.applications.length === 0) {
        await this.loadApplications();
      }
      return this.applications.filter(app => app.team === team);
    } catch (error) {
      this.logger.error('Error in findByTeam:', error);
      throw error;
    }
  }

  async findByStatus(status: ApplicationStatus): Promise<Application[]> {
    try {
      if (this.applications.length === 0) {
        await this.loadApplications();
      }
      return this.applications.filter(app => app.status === status);
    } catch (error) {
      this.logger.error('Error in findByStatus:', error);
      throw error;
    }
  }

  async findByType(type: ApplicationType): Promise<Application[]> {
    try {
      if (this.applications.length === 0) {
        await this.loadApplications();
      }
      return this.applications.filter(app => app.type === type);
    } catch (error) {
      this.logger.error('Error in findByType:', error);
      throw error;
    }
  }

  async assignTestConfigurations(appId: string, testConfigurationIds: string[]): Promise<Application> {
    const application = await this.findOne(appId);

    // Validate that all test configuration IDs exist
    for (const configId of testConfigurationIds) {
      try {
        await this.testConfigurationsService.findOne(configId);
      } catch (error) {
        throw new BadRequestException(`Test configuration with ID "${configId}" not found`);
      }
    }

    // Update the application's test configuration IDs
    application.testConfigurationIds = testConfigurationIds;
    application.updatedAt = new Date();
    await this.saveApplications();

    return application;
  }

  async getTestConfigurations(appId: string, expand: boolean = false): Promise<string[] | any[]> {
    const application = await this.findOne(appId);
    
    if (!application.testConfigurationIds || application.testConfigurationIds.length === 0) {
      return [];
    }

    if (!expand) {
      return application.testConfigurationIds;
    }

    // Return full test configuration objects
    const configs = [];
    for (const configId of application.testConfigurationIds) {
      try {
        const config = await this.testConfigurationsService.findOne(configId);
        configs.push(config);
      } catch (error) {
        this.logger.warn(`Test configuration ${configId} not found, skipping`);
      }
    }
    return configs;
  }

  async runTests(
    appId: string,
    metadata?: { buildId?: string; runId?: string; commitSha?: string; branch?: string }
  ): Promise<{
    status: 'passed' | 'failed' | 'partial';
    totalTests: number;
    passed: number;
    failed: number;
    results: any[];
  }> {
    const application = await this.findOne(appId);

    if (!application.testConfigurationIds || application.testConfigurationIds.length === 0) {
      return {
        status: 'passed',
        totalTests: 0,
        passed: 0,
        failed: 0,
        results: [],
      };
    }

    const results = [];
    let passed = 0;
    let failed = 0;

    const startTime = Date.now();

    for (const configId of application.testConfigurationIds) {
      let configName = 'Unknown';
      let configType: string = 'unknown';
      let testStartTime = Date.now();
      let testResult: any = null;
      let testStatus: TestResultStatus = 'error';
      let testPassed = false;
      let testError: any = undefined;

      try {
        // Get config name first for better error messages
        const config = await this.testConfigurationsService.findOne(configId);
        configName = config.name;
        configType = config.type;
        
        this.logger.log(`Running test configuration ${configId} (${configName}) for application ${appId}`);
        testResult = await this.testConfigurationsService.testConfiguration(configId, {
          applicationId: appId,
          buildId: metadata?.buildId,
          runId: metadata?.runId,
          commitSha: metadata?.commitSha,
          branch: metadata?.branch,
        });
        
        testPassed = testResult.passed !== false;
        testStatus = testPassed ? 'passed' : 'failed';
        
        if (testPassed) {
          passed++;
        } else {
          failed++;
        }

        results.push({
          configId,
          configName,
          result: testResult,
          passed: testPassed,
        });
      } catch (error: any) {
        const errorMessage = error.response?.data?.message || error.message || 'Unknown error occurred';
        const errorType = error.constructor?.name || 'Error';
        
        this.logger.error(
          `Error running test configuration ${configId} (${configName}) for application ${appId}: ${errorMessage}`,
          error.stack
        );
        
        testStatus = 'error';
        testPassed = false;
        testError = {
          message: errorMessage,
          type: errorType,
          details: error.response?.data || undefined,
        };
        
        failed++;
        results.push({
          configId,
          configName,
          passed: false,
          error: testError,
        });
      } finally {
        // Save test result (don't fail if storage fails)
        try {
          const testDuration = Date.now() - testStartTime;
          await this.testResultsService.saveResult({
            applicationId: appId,
            applicationName: application.name,
            testConfigurationId: configId,
            testConfigurationName: configName,
            testConfigurationType: configType as any,
            status: testStatus,
            passed: testPassed,
            buildId: metadata?.buildId,
            runId: metadata?.runId,
            commitSha: metadata?.commitSha,
            branch: metadata?.branch,
            timestamp: new Date(),
            duration: testDuration,
            result: testResult,
            error: testError,
            metadata: {
              ...metadata,
            },
          });
        } catch (storageError: any) {
          // Log but don't fail the test run if storage fails
          this.logger.warn(`Failed to save test result for ${configId}: ${storageError.message}`);
        }
      }
    }

    // Update last test time
    application.lastTestAt = new Date();
    application.updatedAt = new Date();
    await this.saveApplications();

    const status = failed === 0 ? 'passed' : (passed === 0 ? 'failed' : 'partial');

    return {
      status,
      totalTests: results.length,
      passed,
      failed,
      results,
    };
  }

  async findApplicationsUsingConfig(configId: string): Promise<Application[]> {
    return this.applications.filter(
      app => app.testConfigurationIds && app.testConfigurationIds.includes(configId)
    );
  }
}

