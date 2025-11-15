import { Injectable, NotFoundException, ConflictException, BadRequestException, Inject, forwardRef, Logger } from '@nestjs/common';
import { CreateApplicationDto, ApplicationType, ApplicationStatus } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { Application, TestConfigurationOverride, ValidatorOverride } from './entities/application.entity';
import { TestConfigurationsService } from '../test-configurations/test-configurations.service';
import { TestResultsService } from '../test-results/test-results.service';
import { TestResultStatus } from '../test-results/entities/test-result.entity';
import { SecurityAuditLogService, SecurityAuditEventType } from '../security/audit-log.service';
import { ValidatorsService } from '../validators/validators.service';
import { TestHarnessesService } from '../test-harnesses/test-harnesses.service';
import { TestBatteriesService } from '../test-batteries/test-batteries.service';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ApplicationsService {
  private readonly logger = new Logger(ApplicationsService.name);
  private readonly applicationsFile = path.join(process.cwd(), 'data', 'applications.json');
  private applications: Application[] = [];

  /**
   * Mapping from test configuration types to validator testTypes.
   * This determines which validators should be checked before running a test configuration.
   */
  private readonly CONFIG_TYPE_TO_VALIDATOR_TYPES: Record<string, string[]> = {
    'rls-cls': ['rls-cls', 'access-control'],
    'network-policy': ['network-policy'],
    'dlp': ['dlp'],
    'api-gateway': ['api-gateway'],
    'distributed-systems': ['distributed-systems', 'access-control'],
    'api-security': ['api-security'],
    'data-pipeline': ['data-pipeline'],
  };

  constructor(
    @Inject(forwardRef(() => TestConfigurationsService))
    private readonly testConfigurationsService: TestConfigurationsService,
    @Inject(forwardRef(() => TestResultsService))
    private readonly testResultsService: TestResultsService,
    @Inject(forwardRef(() => SecurityAuditLogService))
    private readonly auditLogService: SecurityAuditLogService,
    @Inject(forwardRef(() => ValidatorsService))
    private readonly validatorsService: ValidatorsService,
    @Inject(forwardRef(() => TestHarnessesService))
    private readonly testHarnessesService: TestHarnessesService,
    @Inject(forwardRef(() => TestBatteriesService))
    private readonly testBatteriesService: TestBatteriesService,
  ) {
    // Load applications asynchronously
    this.loadApplications().then(() => {
      // Run migration to ensure all applications have override fields
      this.migrateApplications().catch(err => {
        this.logger.warn('Error running application migration:', err);
      });
    }).catch(err => {
      console.error('Error loading applications on startup:', err);
    });
  }

  private async migrateApplications(): Promise<void> {
    try {
      let updated = 0;
      for (let i = 0; i < this.applications.length; i++) {
        const app = this.applications[i];
        if (!app.testConfigurationOverrides || !app.validatorOverrides) {
          this.applications[i] = {
            ...app,
            testConfigurationOverrides: app.testConfigurationOverrides || {},
            validatorOverrides: app.validatorOverrides || {},
          };
          updated++;
        }
      }
      if (updated > 0) {
        await this.saveApplications();
        this.logger.log(`Migration completed: Updated ${updated} application(s) with override fields`);
      }
    } catch (error) {
      this.logger.error('Error during application migration:', error);
    }
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
          testConfigurationOverrides: app.testConfigurationOverrides || {},
          validatorOverrides: app.validatorOverrides || {},
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

    // Filter test configurations based on overrides
    const enabledConfigIds = [];
    for (const configId of application.testConfigurationIds) {
      const isEnabled = await this.isTestConfigurationEnabled(appId, configId);
      if (isEnabled) {
        enabledConfigIds.push(configId);
      } else {
        this.logger.log(`Skipping test configuration ${configId} for application ${appId} (disabled by override)`);
      }
    }

    if (enabledConfigIds.length === 0) {
      this.logger.warn(`No enabled test configurations for application ${appId}`);
      return {
        status: 'passed',
        totalTests: 0,
        passed: 0,
        failed: 0,
        results: [],
      };
    }

    for (const configId of enabledConfigIds) {
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
        
        // Check if validators are enabled for this test configuration type
        const validatorsEnabled = await this.areValidatorsEnabledForTestConfig(appId, configType);
        if (!validatorsEnabled) {
          this.logger.log(`Skipping test configuration ${configId} (${configName}) for application ${appId} (validator disabled by override)`);
          results.push({
            configId,
            configName,
            configType,
            passed: false,
            error: {
              message: 'Test configuration skipped: validator disabled by override',
              type: 'ValidatorDisabledException',
              details: {
                statusCode: 200,
                message: 'Test configuration skipped: validator disabled by override',
              },
            },
          });
          failed++;
          continue;
        }
        
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

  async toggleTestConfiguration(
    appId: string,
    configId: string,
    enabled: boolean,
    reason?: string,
    userId?: string,
    username?: string,
  ): Promise<Application> {
    const application = await this.findOne(appId);

    // Verify the test configuration exists and is assigned to this application
    if (!application.testConfigurationIds || !application.testConfigurationIds.includes(configId)) {
      throw new BadRequestException(
        `Test configuration "${configId}" is not assigned to application "${appId}"`
      );
    }

    await this.testConfigurationsService.findOne(configId); // Verify config exists

    // Initialize overrides if needed
    if (!application.testConfigurationOverrides) {
      application.testConfigurationOverrides = {};
    }

    // Set or update the override
    application.testConfigurationOverrides[configId] = {
      enabled,
      reason,
      updatedBy: username || userId,
      updatedAt: new Date(),
    };

    application.updatedAt = new Date();
    await this.saveApplications();

    // Audit log
    if (this.auditLogService) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.CONFIG_CHANGED,
        action: enabled ? 'enable-test-config' : 'disable-test-config',
        description: `${enabled ? 'Enabled' : 'Disabled'} test configuration "${configId}" for application "${appId}"${reason ? `: ${reason}` : ''}`,
        userId,
        username,
        resourceType: 'application',
        resourceId: appId,
        resourceName: application.name,
        application: appId,
        team: application.team,
        success: true,
        metadata: {
          configId,
          enabled,
          reason,
        },
      });
    }

    return application;
  }

  async toggleValidator(
    appId: string,
    validatorId: string,
    enabled: boolean,
    reason?: string,
    userId?: string,
    username?: string,
  ): Promise<Application> {
    const application = await this.findOne(appId);

    // Verify the validator exists
    await this.validatorsService.findOne(validatorId);

    // Initialize overrides if needed
    if (!application.validatorOverrides) {
      application.validatorOverrides = {};
    }

    // Set or update the override
    application.validatorOverrides[validatorId] = {
      enabled,
      reason,
      updatedBy: username || userId,
      updatedAt: new Date(),
    };

    application.updatedAt = new Date();
    await this.saveApplications();

    // Audit log
    if (this.auditLogService) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.CONFIG_CHANGED,
        action: enabled ? 'enable-validator' : 'disable-validator',
        description: `${enabled ? 'Enabled' : 'Disabled'} validator "${validatorId}" for application "${appId}"${reason ? `: ${reason}` : ''}`,
        userId,
        username,
        resourceType: 'application',
        resourceId: appId,
        resourceName: application.name,
        application: appId,
        team: application.team,
        success: true,
        metadata: {
          validatorId,
          enabled,
          reason,
        },
      });
    }

    return application;
  }

  async removeTestConfigurationOverride(
    appId: string,
    configId: string,
    userId?: string,
    username?: string,
  ): Promise<Application> {
    const application = await this.findOne(appId);

    if (!application.testConfigurationOverrides || !application.testConfigurationOverrides[configId]) {
      throw new BadRequestException(
        `No override exists for test configuration "${configId}" on application "${appId}"`
      );
    }

    delete application.testConfigurationOverrides[configId];

    // Clean up empty override object
    if (Object.keys(application.testConfigurationOverrides).length === 0) {
      delete application.testConfigurationOverrides;
    }

    application.updatedAt = new Date();
    await this.saveApplications();

    // Audit log
    if (this.auditLogService) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.CONFIG_CHANGED,
        action: 'remove-test-config-override',
        description: `Removed override for test configuration "${configId}" on application "${appId}"`,
        userId,
        username,
        resourceType: 'application',
        resourceId: appId,
        resourceName: application.name,
        application: appId,
        team: application.team,
        success: true,
        metadata: {
          configId,
        },
      });
    }

    return application;
  }

  async removeValidatorOverride(
    appId: string,
    validatorId: string,
    userId?: string,
    username?: string,
  ): Promise<Application> {
    const application = await this.findOne(appId);

    if (!application.validatorOverrides || !application.validatorOverrides[validatorId]) {
      throw new BadRequestException(
        `No override exists for validator "${validatorId}" on application "${appId}"`
      );
    }

    delete application.validatorOverrides[validatorId];

    // Clean up empty override object
    if (Object.keys(application.validatorOverrides).length === 0) {
      delete application.validatorOverrides;
    }

    application.updatedAt = new Date();
    await this.saveApplications();

    // Audit log
    if (this.auditLogService) {
      await this.auditLogService.log({
        type: SecurityAuditEventType.CONFIG_CHANGED,
        action: 'remove-validator-override',
        description: `Removed override for validator "${validatorId}" on application "${appId}"`,
        userId,
        username,
        resourceType: 'application',
        resourceId: appId,
        resourceName: application.name,
        application: appId,
        team: application.team,
        success: true,
        metadata: {
          validatorId,
        },
      });
    }

    return application;
  }

  async getTestConfigurationStatus(appId: string): Promise<Array<{
    configId: string;
    name: string;
    type: string;
    enabled: boolean;
    override?: TestConfigurationOverride;
  }>> {
    const application = await this.findOne(appId);

    if (!application.testConfigurationIds || application.testConfigurationIds.length === 0) {
      return [];
    }

    const statuses = [];
    for (const configId of application.testConfigurationIds) {
      try {
        const config = await this.testConfigurationsService.findOne(configId);
        const override = application.testConfigurationOverrides?.[configId];
        const enabled = override ? override.enabled : (config.enabled !== false);

        statuses.push({
          configId,
          name: config.name,
          type: config.type,
          enabled,
          override,
        });
      } catch (error) {
        this.logger.warn(`Test configuration ${configId} not found, skipping`);
      }
    }

    return statuses;
  }

  async getValidatorStatus(appId: string): Promise<Array<{
    validatorId: string;
    name: string;
    testType: string;
    enabled: boolean;
    override?: ValidatorOverride;
  }>> {
    const application = await this.findOne(appId);
    const allValidators = await this.validatorsService.findAll();

    const statuses = [];
    for (const validator of allValidators) {
      const override = application.validatorOverrides?.[validator.id];
      // Validator is enabled if:
      // 1. It's globally enabled AND
      // 2. Either no override exists OR override says enabled
      const enabled = validator.enabled && (override ? override.enabled : true);

      statuses.push({
        validatorId: validator.id,
        name: validator.name,
        testType: validator.testType,
        enabled,
        override,
      });
    }

    return statuses;
  }

  async isTestConfigurationEnabled(appId: string, configId: string): Promise<boolean> {
    const application = await this.findOne(appId);
    const override = application.testConfigurationOverrides?.[configId];
    
    if (override !== undefined) {
      return override.enabled;
    }

    // If no override, check the test configuration's global enabled status
    try {
      const config = await this.testConfigurationsService.findOne(configId);
      return config.enabled !== false;
    } catch {
      return false;
    }
  }

  async isValidatorEnabled(appId: string, validatorId: string): Promise<boolean> {
    const application = await this.findOne(appId);
    
    try {
      const validator = await this.validatorsService.findOne(validatorId);
      const override = application.validatorOverrides?.[validatorId];

      // Validator must be globally enabled
      if (!validator.enabled) {
        return false;
      }

      // If override exists, use it; otherwise default to enabled (since global is enabled)
      if (override !== undefined) {
        return override.enabled;
      }

      return true;
    } catch (error) {
      // Validator not found (may have been deleted)
      this.logger.warn(`Validator ${validatorId} not found when checking enabled status for application ${appId}`);
      return false;
    }
  }

  /**
   * Get validator IDs for a given test configuration type.
   * Returns validators that match the testTypes associated with the config type.
   */
  private async getValidatorsForTestConfigurationType(configType: string): Promise<string[]> {
    const validatorTypes = this.CONFIG_TYPE_TO_VALIDATOR_TYPES[configType];
    
    if (!validatorTypes || validatorTypes.length === 0) {
      // No validators mapped for this config type - backward compatible
      return [];
    }

    try {
      const allValidators = await this.validatorsService.findAll();
      const matchingValidators = allValidators
        .filter(v => validatorTypes.includes(v.testType))
        .map(v => v.id);
      
      return matchingValidators;
    } catch (error) {
      this.logger.warn(`Error finding validators for test configuration type ${configType}:`, error);
      return [];
    }
  }

  /**
   * Check if all validators required for a test configuration type are enabled for the application.
   * Returns true if:
   * - No validators exist for the test config type (backward compatible)
   * - All validators for the test config type are enabled
   * Returns false if any validator is disabled.
   */
  async areValidatorsEnabledForTestConfig(appId: string, configType: string): Promise<boolean> {
    const validatorIds = await this.getValidatorsForTestConfigurationType(configType);
    
    // If no validators found for this config type, allow test (backward compatible)
    if (validatorIds.length === 0) {
      return true;
    }

    // Check each validator - all must be enabled
    for (const validatorId of validatorIds) {
      const isEnabled = await this.isValidatorEnabled(appId, validatorId);
      if (!isEnabled) {
        this.logger.log(`Validator ${validatorId} is disabled for application ${appId}, blocking test configuration type ${configType}`);
        return false;
      }
    }

    return true;
  }

  async bulkToggleTestConfigurations(
    appId: string,
    items: Array<{ id: string; enabled: boolean; reason?: string }>,
    userId?: string,
    username?: string,
  ): Promise<Application> {
    const application = await this.findOne(appId);

    for (const item of items) {
      await this.toggleTestConfiguration(
        appId,
        item.id,
        item.enabled,
        item.reason,
        userId,
        username,
      );
    }

    return application;
  }

  async bulkToggleValidators(
    appId: string,
    items: Array<{ id: string; enabled: boolean; reason?: string }>,
    userId?: string,
    username?: string,
  ): Promise<Application> {
    const application = await this.findOne(appId);

    for (const item of items) {
      await this.toggleValidator(
        appId,
        item.id,
        item.enabled,
        item.reason,
        userId,
        username,
      );
    }

    return application;
  }

  /**
   * Get test harnesses assigned to an application
   */
  async getAssignedTestHarnesses(applicationId: string): Promise<any[]> {
    await this.loadApplications();
    // Verify application exists
    await this.findOne(applicationId);
    return this.testHarnessesService.findByApplication(applicationId);
  }

  /**
   * Get test batteries that contain harnesses assigned to an application
   */
  async getAssignedTestBatteries(applicationId: string): Promise<any[]> {
    await this.loadApplications();
    // Verify application exists
    await this.findOne(applicationId);
    const assignedHarnesses = await this.getAssignedTestHarnesses(applicationId);
    const assignedHarnessIds = assignedHarnesses.map(h => h.id);
    
    if (assignedHarnessIds.length === 0) {
      return [];
    }

    const allBatteries = await this.testBatteriesService.findAll();
    return allBatteries.filter(battery => 
      battery.harnessIds && battery.harnessIds.some(harnessId => assignedHarnessIds.includes(harnessId))
    );
  }
}

