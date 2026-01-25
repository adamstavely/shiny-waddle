import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  Inject,
  forwardRef,
  OnModuleInit,
} from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { TestEntity } from './entities/test.entity';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { Test, TestVersion, AccessControlTest, TestType } from '../../../heimdall-framework/core/types';
import { PoliciesService } from '../policies/policies.service';
import { getDomainFromTestType } from '../../../heimdall-framework/core/domain-mapping';
import { TestDiscoveryService } from './test-discovery.service';

@Injectable()
export class TestsService implements OnModuleInit {
  private readonly logger = new Logger(TestsService.name);
  private readonly testsFile = path.join(process.cwd(), 'data', 'tests.json');
  private tests: TestEntity[] = [];

  constructor(
    private readonly moduleRef: ModuleRef,
    private readonly discoveryService: TestDiscoveryService,
  ) {}

  async onModuleInit() {
    // Load existing tests from file first
    await this.loadTests();
    // Auto-discover tests from framework on module initialization
    await this.discoverAndRegisterTests();
  }

  /**
   * Discover tests from framework and register them if they don't exist
   */
  private async discoverAndRegisterTests(): Promise<void> {
    try {
      const discoveredTests = await this.discoveryService.discoverTests();
      
      for (const discovered of discoveredTests) {
        // Check if test already exists
        const existing = this.tests.find(t => t.id === discovered.id);
        
        if (!existing) {
          // Add discovered test
          this.tests.push(discovered);
          this.logger.log(`Auto-registered test: ${discovered.name} (${discovered.id})`);
        } else {
          // Update metadata if version changed or description improved
          if (existing.version < discovered.version || 
              (existing.description === '' && discovered.description !== '')) {
            existing.version = discovered.version;
            existing.description = discovered.description || existing.description;
            existing.updatedAt = new Date();
            this.logger.log(`Updated test metadata: ${discovered.name} (${discovered.id})`);
          }
        }
      }

      // Save updated tests list
      if (discoveredTests.length > 0) {
        await this.saveTests();
      }
    } catch (error: any) {
      this.logger.error(`Error discovering tests: ${error.message}`, error.stack);
    }
  }

  private async loadTests(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.testsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.testsFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.tests = [];
          await this.saveTests();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Tests file does not contain an array, initializing empty');
          this.tests = [];
          await this.saveTests();
          return;
        }
        this.tests = parsed.map((t: any) => ({
          ...t,
          createdAt: t.createdAt ? new Date(t.createdAt) : new Date(),
          updatedAt: t.updatedAt ? new Date(t.updatedAt) : new Date(),
          versionHistory: (t.versionHistory || []).map((v: any) => ({
            ...v,
            changedAt: v.changedAt ? new Date(v.changedAt) : new Date(),
          })),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.tests = [];
          await this.saveTests();
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error in tests file, initializing empty:', readError.message);
          this.tests = [];
          await this.saveTests();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading tests:', error);
      this.tests = [];
    }
  }

  private async saveTests(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.testsFile), { recursive: true });
      await fs.writeFile(this.testsFile, JSON.stringify(this.tests, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving tests:', error);
      throw error;
    }
  }

  private async validatePolicies(policyIds: string[]): Promise<void> {
    try {
      const policiesService = this.moduleRef.get(PoliciesService, { strict: false });
      for (const policyId of policyIds) {
        const policy = await policiesService.findOne(policyId);
        if (!policy) {
          throw new BadRequestException(`Policy ${policyId} not found`);
        }
      }
    } catch (error: any) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      this.logger.warn('Could not validate policies (PoliciesService may not be available):', error.message);
    }
  }

  private detectChanges(oldTest: TestEntity, newTest: Partial<TestEntity>): string[] {
    const changes: string[] = [];
    const fieldsToCheck = ['name', 'description', 'policyId', 'inputs', 'expected'];
    
    for (const field of fieldsToCheck) {
      if (field in newTest && JSON.stringify(oldTest[field]) !== JSON.stringify(newTest[field])) {
        changes.push(field);
      }
    }
    
    return changes;
  }

  async create(dto: CreateTestDto, createdBy?: string): Promise<TestEntity> {
    await this.loadTests();

    // Validate policy for access-control tests
    if (dto.testType === 'access-control' && dto.policyId) {
      await this.validatePolicies([dto.policyId]);
    }

    // Auto-populate domain from testType if not provided
    const domain = dto.domain || getDomainFromTestType(dto.testType as TestType);
    
    // Validate that provided domain matches testType mapping
    if (dto.domain) {
      const expectedDomain = getDomainFromTestType(dto.testType as TestType);
      if (dto.domain !== expectedDomain) {
        throw new BadRequestException(
          `Domain "${dto.domain}" does not match testType "${dto.testType}" (expected: "${expectedDomain}")`
        );
      }
    }

    const test: TestEntity = {
      id: uuidv4(),
      ...dto,
      domain,
      version: 1,
      versionHistory: [],
      createdAt: new Date(),
      updatedAt: new Date(),
      createdBy,
      lastModifiedBy: createdBy,
    } as TestEntity;

    this.tests.push(test);
    await this.saveTests();

    this.logger.log(`Created test ${test.id} (${test.name})`);
    return test;
  }

  async findAll(filters?: { testType?: string; policyId?: string; domain?: string }): Promise<TestEntity[]> {
    await this.loadTests();
    
    let filtered = [...this.tests];
    
    if (filters?.testType) {
      filtered = filtered.filter(t => t.testType === filters.testType);
    }
    
    if (filters?.domain) {
      filtered = filtered.filter(t => t.domain === filters.domain);
    }
    
    if (filters?.policyId) {
      filtered = filtered.filter(t => {
        if (t.testType === 'access-control') {
          const accessTest = t as AccessControlTest;
          return accessTest.policyId === filters.policyId;
        }
        return false;
      });
    }
    
    return filtered;
  }

  async findOne(id: string): Promise<TestEntity> {
    await this.loadTests();
    const test = this.tests.find(t => t.id === id);
    if (!test) {
      throw new NotFoundException(`Test with ID ${id} not found`);
    }
    return test;
  }

  async findByPolicy(policyId: string): Promise<TestEntity[]> {
    await this.loadTests();
    return this.tests.filter(t => {
      if (t.testType === 'access-control') {
        const accessTest = t as AccessControlTest;
        return accessTest.policyId === policyId;
      }
      return false;
    });
  }

  async findOneVersion(id: string, version: number): Promise<TestEntity> {
    const test = await this.findOne(id);
    
    if (version === test.version) {
      return test;
    }
    
    // Find in version history
    const versionHistory = test.versionHistory || [];
    const versionEntry = versionHistory.find(v => v.version === version);
    
    if (!versionEntry) {
      throw new NotFoundException(`Version ${version} not found for test ${id}`);
    }
    
    // Reconstruct test at that version
    return {
      ...test,
      ...versionEntry.testConfiguration,
      version: versionEntry.version,
    } as TestEntity;
  }

  async update(
    id: string,
    dto: UpdateTestDto,
    changedBy?: string,
    changeReason?: string,
  ): Promise<TestEntity> {
    await this.loadTests();
    
    const testIndex = this.tests.findIndex(t => t.id === id);
    if (testIndex === -1) {
      throw new NotFoundException(`Test with ID ${id} not found`);
    }
    
    const oldTest = { ...this.tests[testIndex] };
    
    // Validate policy if updating access-control test
    if (dto.testType === 'access-control' || oldTest.testType === 'access-control') {
      const policyId = dto.policyId || (oldTest as AccessControlTest).policyId;
      if (policyId) {
        await this.validatePolicies([policyId]);
      }
    }
    
    // Detect changes
    const changes = this.detectChanges(oldTest, dto);
    
    // Create version history entry
    const versionHistory = oldTest.versionHistory || [];
    const newVersion = oldTest.version + 1;
    
    versionHistory.push({
      version: oldTest.version,
      testConfiguration: {
        name: oldTest.name,
        description: oldTest.description,
        ...(oldTest.testType === 'access-control' ? {
          policyId: (oldTest as AccessControlTest).policyId,
          inputs: (oldTest as AccessControlTest).inputs,
          expected: (oldTest as AccessControlTest).expected,
        } : {}),
      },
      changedBy: oldTest.lastModifiedBy,
      changeReason,
      changedAt: new Date(),
      changes,
    });
    
    // Auto-update domain if testType changes
    let domain = oldTest.domain;
    if (dto.testType && dto.testType !== oldTest.testType) {
      domain = getDomainFromTestType(dto.testType as TestType);
    } else if (dto.domain) {
      // Validate provided domain matches testType
      const expectedDomain = getDomainFromTestType((dto.testType || oldTest.testType) as TestType);
      if (dto.domain !== expectedDomain) {
        throw new BadRequestException(
          `Domain "${dto.domain}" does not match testType "${dto.testType || oldTest.testType}" (expected: "${expectedDomain}")`
        );
      }
      domain = dto.domain;
    }
    
    // Keep only last 10 versions
    if (versionHistory.length > 10) {
      versionHistory.shift();
    }
    
    // Update test
    const updatedTest: TestEntity = {
      ...oldTest,
      ...dto,
      domain,
      version: newVersion,
      versionHistory,
      updatedAt: new Date(),
      lastModifiedBy: changedBy,
    } as TestEntity;
    
    this.tests[testIndex] = updatedTest;
    await this.saveTests();
    
    this.logger.log(`Updated test ${id} to version ${newVersion}`);
    return updatedTest;
  }

  async remove(id: string): Promise<void> {
    await this.loadTests();
    
    const testIndex = this.tests.findIndex(t => t.id === id);
    if (testIndex === -1) {
      throw new NotFoundException(`Test with ID ${id} not found`);
    }
    
    this.tests.splice(testIndex, 1);
    await this.saveTests();
    
    this.logger.log(`Deleted test ${id}`);
  }

  async getUsedInSuites(testId: string): Promise<any[]> {
    await this.loadTests();
    const test = await this.findOne(testId);
    if (!test) {
      return [];
    }

    // Read test suites file to find which suites use this test
    const suitesFile = path.join(process.cwd(), 'data', 'test-suites.json');
    try {
      const data = await fs.readFile(suitesFile, 'utf-8');
      if (!data || data.trim() === '') {
        return [];
      }
      const suites = JSON.parse(data);
      return suites
        .filter((s: any) => s.testIds && s.testIds.includes(testId))
        .map((s: any) => ({
          id: s.id,
          name: s.name,
        }));
    } catch (err) {
      this.logger.error('Error getting suites for test:', err);
      return [];
    }
  }
}

