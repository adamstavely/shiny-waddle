import { Injectable, NotFoundException, ConflictException, BadRequestException, Inject, forwardRef, Logger } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { CreateApplicationDto, ApplicationType, ApplicationStatus } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { Application, ApplicationInfrastructure, ValidatorOverride } from './entities/application.entity';
import { TestResultsService } from '../test-results/test-results.service';
import { TestResultStatus } from '../test-results/entities/test-result.entity';
import { SecurityAuditLogService, SecurityAuditEventType } from '../security/audit-log.service';
import { ValidatorsService } from '../validators/validators.service';
import { TestHarnessesService } from '../test-harnesses/test-harnesses.service';
import { TestBatteriesService } from '../test-batteries/test-batteries.service';
import { ContextDetectorService } from '../cicd/context-detector.service';
import { getDomainFromTestType, getDomainDisplayName } from '../../../heimdall-framework/core/domain-mapping';
import { TestType } from '../../../heimdall-framework/core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ApplicationsService {
  private readonly logger = new Logger(ApplicationsService.name);
  private readonly applicationsFile = path.join(process.cwd(), 'data', 'applications.json');
  private applications: Application[] = [];


  constructor(
    @Inject(forwardRef(() => TestResultsService))
    private readonly testResultsService: TestResultsService,
    @Inject(forwardRef(() => ValidatorsService))
    private readonly validatorsService: ValidatorsService,
    private readonly contextDetector: ContextDetectorService,
    private readonly moduleRef: ModuleRef,
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
        if (!app.validatorOverrides) {
          this.applications[i] = {
            ...app,
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

    // Validate infrastructure if provided
    if (createApplicationDto.infrastructure) {
      this.validateInfrastructure(createApplicationDto.infrastructure);
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
      infrastructure: createApplicationDto.infrastructure, // NEW
      registeredAt: new Date(),
      updatedAt: new Date(),
    };

    this.applications.push(application);
    await this.saveApplications();

    return application;
  }

  /**
   * Validate application infrastructure
   */
  private validateInfrastructure(infrastructure: ApplicationInfrastructure): void {
    // Validate databases
    if (infrastructure.databases) {
      for (const db of infrastructure.databases) {
        if (!db.id || !db.name) {
          throw new BadRequestException('Database infrastructure must have id and name');
        }
        if (!db.host || !db.port || !db.database) {
          throw new BadRequestException('Database infrastructure must have host, port, and database');
        }
        if (!db.type) {
          throw new BadRequestException('Database infrastructure must have type');
        }
      }
    }

    // Validate network segments
    if (infrastructure.networkSegments) {
      for (const segment of infrastructure.networkSegments) {
        if (!segment.id || !segment.name) {
          throw new BadRequestException('Network segment infrastructure must have id and name');
        }
      }
    }

    // Additional validation for other infrastructure types can be added here
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

    // Validate infrastructure if provided
    if (updateData.infrastructure) {
      this.validateInfrastructure(updateData.infrastructure);
    }

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

    // Auto-detect CI/CD context if not provided
    const detectedContext = this.contextDetector.detectContext();
    const mergedContext = this.contextDetector.mergeContext(
      metadata || {},
      detectedContext
    );

    // Use merged context for metadata
    const executionMetadata = {
      buildId: mergedContext.buildId || metadata?.buildId,
      runId: mergedContext.runId || metadata?.runId,
      commitSha: mergedContext.commitSha || metadata?.commitSha,
      branch: mergedContext.branch || metadata?.branch,
    };

    if (detectedContext.ciPlatform) {
      this.logger.log(`Detected CI/CD platform: ${detectedContext.ciPlatform} for test execution`);
    }

    // NOTE: Test execution via Application.infrastructure and Test Suites is not yet fully implemented
    // Current behavior: Returns empty results when infrastructure is not configured
    // Future implementation should:
    // 1. Find test suites for this application
    // 2. Use infrastructure configuration to set up test environment
    // 3. Execute tests via test harness/battery system
    // 4. Return actual test results
    this.logger.warn(`runTests called for application ${appId} but test execution via infrastructure is not yet implemented`);
    
    if (!application.infrastructure) {
      return {
        status: 'passed',
        totalTests: 0,
        passed: 0,
        failed: 0,
        results: [],
      };
    }
    
    return {
      status: 'passed',
      totalTests: 0,
      passed: 0,
      failed: 0,
      results: [],
    };
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
    try {
      const auditLogService = this.moduleRef.get(SecurityAuditLogService, { strict: false });
      if (auditLogService) {
        await auditLogService.log({
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
    } catch (err) {
      this.logger.warn('Failed to log audit event:', err);
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
    try {
      const auditLogService = this.moduleRef.get(SecurityAuditLogService, { strict: false });
      if (auditLogService) {
        await auditLogService.log({
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
    } catch (err) {
      this.logger.warn('Failed to log audit event:', err);
    }

    return application;
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
    const testHarnessesService = this.moduleRef.get(TestHarnessesService, { strict: false });
    if (!testHarnessesService) {
      throw new Error('TestHarnessesService not available');
    }
    return testHarnessesService.findByApplication(applicationId);
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

    const testBatteriesService = this.moduleRef.get(TestBatteriesService, { strict: false });
    if (!testBatteriesService) {
      throw new Error('TestBatteriesService not available');
    }
    const allBatteries = await testBatteriesService.findAll();
    return allBatteries.filter(battery => 
      battery.harnessIds && battery.harnessIds.some(harnessId => assignedHarnessIds.includes(harnessId))
    );
  }

  /**
   * Get runs for an application
   */
  async getRuns(applicationId: string, limit?: number): Promise<any[]> {
    await this.loadApplications();
    await this.findOne(applicationId);
    
    const results = await this.testResultsService.query({
      applicationId,
      limit,
    });
    
    // Group results by runId to create battery runs
    const runsByRunId = new Map<string, any>();
    
    for (const result of results) {
      const runId = result.runId || result.id;
      if (!runsByRunId.has(runId)) {
        // Try to find battery name from harness/battery
        const batteryName = result.metadata?.batteryName || 'Unknown Battery';
        runsByRunId.set(runId, {
          id: runId,
          batteryName,
          status: result.status === 'passed' ? 'completed' : result.status === 'failed' ? 'failed' : 'running',
          score: this.calculateScoreFromResults([result]),
          timestamp: result.timestamp,
          environment: result.metadata?.environment || 'N/A',
          harnesses: [],
        });
      }
      
      const run = runsByRunId.get(runId);
      if (result.metadata?.harnessName && !run.harnesses.find((h: any) => h.id === result.metadata.harnessId)) {
        run.harnesses.push({
          id: result.metadata.harnessId,
          name: result.metadata.harnessName,
        });
      }
    }
    
    return Array.from(runsByRunId.values()).sort((a, b) => 
      b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  /**
   * Get issues across all applications
   */
  async getAllIssues(limit?: number, priority?: string): Promise<any[]> {
    try {
      await this.loadApplications();
      
      // Get failed test results as issues from all applications
      let results: any[] = [];
      try {
        results = await this.testResultsService.query({
          status: 'failed',
          limit: limit ? limit * 2 : undefined, // Get more to account for filtering
        });
      } catch (queryError) {
        // If query fails, return empty array instead of throwing
        this.logger.warn('Error querying test results for issues, returning empty array:', queryError);
        return [];
      }
      
      const issues = results.map(result => ({
        id: result.id,
        title: `Test failed: ${result.testConfigurationName || 'Unknown Test'}`,
        description: result.error || 'Test execution failed',
        domain: this.getDomainFromTestType(result.testConfigurationType || ''),
        priority: this.getPriorityFromResult(result),
        applicationId: result.applicationId,
        applicationName: result.applicationName,
        timestamp: result.timestamp,
      }));
      
      // Filter by priority if specified
      let filteredIssues = issues;
      if (priority) {
        const priorities = priority.split(',');
        filteredIssues = issues.filter(issue => priorities.includes(issue.priority));
      }
      
      // Sort by priority (critical, high, medium, low) and timestamp
      const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      filteredIssues.sort((a, b) => {
        const priorityDiff = (priorityOrder[a.priority as keyof typeof priorityOrder] || 99) - 
                             (priorityOrder[b.priority as keyof typeof priorityOrder] || 99);
        if (priorityDiff !== 0) return priorityDiff;
        return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
      });
      
      // Apply limit after filtering and sorting
      if (limit) {
        return filteredIssues.slice(0, limit);
      }
      
      return filteredIssues;
    } catch (error) {
      this.logger.error('Error in getAllIssues:', error);
      // Return empty array instead of throwing to prevent dashboard from failing
      return [];
    }
  }

  /**
   * Get issues for an application
   */
  async getIssues(applicationId: string, limit?: number, priority?: string): Promise<any[]> {
    await this.loadApplications();
    await this.findOne(applicationId);
    
    // Get failed test results as issues
    const results = await this.testResultsService.query({
      applicationId,
      status: 'failed',
      limit,
    });
    
    const issues = results.map(result => ({
      id: result.id,
      title: `Test failed: ${result.testConfigurationName || 'Unknown Test'}`,
      description: result.error || 'Test execution failed',
      domain: this.getDomainFromTestType(result.testConfigurationType || ''),
      priority: this.getPriorityFromResult(result),
      applicationId,
      applicationName: result.applicationName,
      timestamp: result.timestamp,
    }));
    
    // Filter by priority if specified
    if (priority) {
      const priorities = priority.split(',');
      return issues.filter(issue => priorities.includes(issue.priority));
    }
    
    return issues;
  }

  /**
   * Get compliance score for an application
   */
  async getComplianceScore(applicationId: string): Promise<{ score: number }> {
    await this.loadApplications();
    await this.findOne(applicationId);
    
    const results = await this.testResultsService.query({
      applicationId,
      limit: 100, // Get recent results
    });
    
    if (results.length === 0) {
      return { score: 0 };
    }
    
    const score = this.calculateScoreFromResults(results);
    return { score };
  }

  private calculateScoreFromResults(results: any[]): number {
    if (results.length === 0) return 0;
    const passed = results.filter(r => r.status === 'passed').length;
    return Math.round((passed / results.length) * 100);
  }

  private getDomainFromTestType(testType: string): string {
    // Use centralized domain mapping utility
    try {
      const domain = getDomainFromTestType(testType as TestType);
      return getDomainDisplayName(domain);
    } catch (error) {
      // Fallback for unknown test types
      return 'Other';
    }
  }

  private getPriorityFromResult(result: any): string {
    // Determine priority based on test type and error
    if (result.testConfigurationType === 'api-security' || result.testConfigurationType === 'access-control') {
      return 'critical';
    }
    if (result.error && result.error.includes('critical')) {
      return 'critical';
    }
    if (result.error && result.error.includes('high')) {
      return 'high';
    }
    return 'medium';
  }
}

