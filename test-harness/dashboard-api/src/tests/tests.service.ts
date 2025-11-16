import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { TestEntity } from './entities/test.entity';
import { CreateTestDto } from './dto/create-test.dto';
import { UpdateTestDto } from './dto/update-test.dto';
import { Test, TestVersion, AccessControlTest } from '../../../../core/types';
import { PoliciesService } from '../policies/policies.service';

@Injectable()
export class TestsService {
  private readonly logger = new Logger(TestsService.name);
  private readonly testsFile = path.join(process.cwd(), 'data', 'tests.json');
  private tests: TestEntity[] = [];

  constructor(
    private readonly moduleRef: ModuleRef,
  ) {
    this.loadTests().catch(err => {
      this.logger.error('Error loading tests on startup:', err);
    });
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
    const fieldsToCheck = ['name', 'description', 'policyIds', 'role', 'resource', 'context', 'expectedDecision'];
    
    for (const field of fieldsToCheck) {
      if (field in newTest && JSON.stringify(oldTest[field]) !== JSON.stringify(newTest[field])) {
        changes.push(field);
      }
    }
    
    return changes;
  }

  async create(dto: CreateTestDto, createdBy?: string): Promise<TestEntity> {
    await this.loadTests();

    // Validate policies for access-control tests
    if (dto.testType === 'access-control' && 'policyIds' in dto && dto.policyIds) {
      await this.validatePolicies(dto.policyIds);
    }

    const test: TestEntity = {
      id: uuidv4(),
      ...dto,
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

  async findAll(filters?: { testType?: string; policyId?: string }): Promise<TestEntity[]> {
    await this.loadTests();
    
    let filtered = [...this.tests];
    
    if (filters?.testType) {
      filtered = filtered.filter(t => t.testType === filters.testType);
    }
    
    if (filters?.policyId) {
      filtered = filtered.filter(t => {
        if (t.testType === 'access-control') {
          const accessTest = t as AccessControlTest;
          return accessTest.policyIds?.includes(filters.policyId!);
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
        return accessTest.policyIds?.includes(policyId);
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
    
    // Validate policies if updating access-control test
    if (dto.testType === 'access-control' || oldTest.testType === 'access-control') {
      const policyIds = 'policyIds' in dto ? dto.policyIds : (oldTest as AccessControlTest).policyIds;
      if (policyIds && policyIds.length > 0) {
        await this.validatePolicies(policyIds);
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
          policyIds: (oldTest as AccessControlTest).policyIds,
          role: (oldTest as AccessControlTest).role,
          resource: (oldTest as AccessControlTest).resource,
          context: (oldTest as AccessControlTest).context,
          expectedDecision: (oldTest as AccessControlTest).expectedDecision,
        } : {}),
      },
      changedBy: oldTest.lastModifiedBy,
      changeReason,
      changedAt: new Date(),
      changes,
    });
    
    // Keep only last 10 versions
    if (versionHistory.length > 10) {
      versionHistory.shift();
    }
    
    // Update test
    const updatedTest: TestEntity = {
      ...oldTest,
      ...dto,
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
}

