import { Injectable, NotFoundException, BadRequestException, Logger, Inject, forwardRef } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { TestHarnessEntity } from './entities/test-harness.entity';
import { CreateTestHarnessDto } from './dto/create-test-harness.dto';
import { UpdateTestHarnessDto } from './dto/update-test-harness.dto';
import { TestSuitesService } from '../test-suites/test-suites.service';

@Injectable()
export class TestHarnessesService {
  private readonly logger = new Logger(TestHarnessesService.name);
  private readonly harnessesFile = path.join(process.cwd(), 'data', 'test-harnesses.json');
  private harnesses: TestHarnessEntity[] = [];

  constructor(
    @Inject(forwardRef(() => TestSuitesService))
    private readonly testSuitesService: TestSuitesService,
  ) {
    this.loadHarnesses().catch(err => {
      this.logger.error('Error loading test harnesses on startup:', err);
    });
  }

  private async loadHarnesses(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.harnessesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.harnessesFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.harnesses = [];
          await this.saveHarnesses();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Test harnesses file does not contain an array, initializing empty');
          this.harnesses = [];
          await this.saveHarnesses();
          return;
        }
        this.harnesses = parsed.map((h: any) => ({
          ...h,
          createdAt: h.createdAt ? new Date(h.createdAt) : new Date(),
          updatedAt: h.updatedAt ? new Date(h.updatedAt) : new Date(),
          testSuiteIds: h.testSuiteIds || [],
          applicationIds: h.applicationIds || [],
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.harnesses = [];
          await this.saveHarnesses();
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error in test harnesses file, initializing empty:', readError.message);
          this.harnesses = [];
          await this.saveHarnesses();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading test harnesses:', error);
      this.harnesses = [];
    }
  }

  private async saveHarnesses(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.harnessesFile), { recursive: true });
      await fs.writeFile(this.harnessesFile, JSON.stringify(this.harnesses, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving test harnesses:', error);
      throw error;
    }
  }

  async create(dto: CreateTestHarnessDto): Promise<TestHarnessEntity> {
    await this.loadHarnesses();

    // Validate that all suites match the harness domain
    if (dto.testSuiteIds && dto.testSuiteIds.length > 0) {
      const suites = await this.testSuitesService.findAll();
      for (const suiteId of dto.testSuiteIds) {
        const suite = suites.find(s => s.id === suiteId);
        if (!suite) {
          throw new BadRequestException(`Test suite with ID "${suiteId}" not found`);
        }
        if (suite.domain !== dto.domain) {
          throw new BadRequestException(
            `Test suite "${suite.name}" (domain: ${suite.domain}) does not match harness domain "${dto.domain}". ` +
            `All suites in a harness must have the same domain.`
          );
        }
      }
    }

    // Check for duplicate name
    const existing = this.harnesses.find(h => h.name === dto.name);
    if (existing) {
      throw new BadRequestException(`Test harness with name "${dto.name}" already exists`);
    }

    const now = new Date();
    const harness: TestHarnessEntity = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description,
      domain: dto.domain,
      testType: dto.testType, // Keep for backward compatibility
      testSuiteIds: dto.testSuiteIds || [],
      applicationIds: dto.applicationIds || [],
      team: dto.team,
      createdAt: now,
      updatedAt: now,
    };

    this.harnesses.push(harness);
    await this.saveHarnesses();

    this.logger.log(`Created test harness: ${harness.id} (${harness.name})`);
    return harness;
  }

  async findAll(): Promise<TestHarnessEntity[]> {
    await this.loadHarnesses();
    return [...this.harnesses];
  }

  async findOne(id: string): Promise<TestHarnessEntity> {
    await this.loadHarnesses();
    const harness = this.harnesses.find(h => h.id === id);
    if (!harness) {
      throw new NotFoundException(`Test harness with ID "${id}" not found`);
    }
    return harness;
  }

  async update(id: string, dto: UpdateTestHarnessDto): Promise<TestHarnessEntity> {
    await this.loadHarnesses();
    const index = this.harnesses.findIndex(h => h.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test harness with ID "${id}" not found`);
    }

    const existing = this.harnesses[index];
    const testType = dto.testType || existing.testType;

    // Validate testType if provided
    if (dto.testType) {
      const validTestTypes = [
        'access-control',
        'data-behavior',
        'dataset-health',
        'rls-cls',
        'network-policy',
        'dlp',
        'api-gateway',
        'distributed-systems',
        'api-security',
        'data-pipeline',
      ];
      if (!validTestTypes.includes(dto.testType)) {
        throw new BadRequestException(
          `Invalid testType "${dto.testType}". Valid types are: ${validTestTypes.join(', ')}`
        );
      }
    }

    // Validate that all suites match the harness type
    const suiteIdsToCheck = dto.testSuiteIds !== undefined ? dto.testSuiteIds : existing.testSuiteIds;
    if (suiteIdsToCheck.length > 0) {
      const suites = await this.testSuitesService.findAll();
      for (const suiteId of suiteIdsToCheck) {
        const suite = suites.find(s => s.id === suiteId);
        if (!suite) {
          throw new BadRequestException(`Test suite with ID "${suiteId}" not found`);
        }
        if (suite.testType !== testType) {
          throw new BadRequestException(
            `Test suite "${suite.name}" (${suite.testType}) does not match harness type "${testType}". ` +
            `All suites in a harness must have the same type.`
          );
        }
      }
    }

    // Check for duplicate name if name is being updated
    if (dto.name && dto.name !== existing.name) {
      const duplicate = this.harnesses.find(h => h.name === dto.name && h.id !== id);
      if (duplicate) {
        throw new BadRequestException(`Test harness with name "${dto.name}" already exists`);
      }
    }

    const updated: TestHarnessEntity = {
      ...existing,
      ...dto,
      testType: testType,
      updatedAt: new Date(),
    };

    this.harnesses[index] = updated;
    await this.saveHarnesses();

    this.logger.log(`Updated test harness: ${id}`);
    return updated;
  }

  async delete(id: string): Promise<void> {
    await this.loadHarnesses();
    const index = this.harnesses.findIndex(h => h.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test harness with ID "${id}" not found`);
    }

    this.harnesses.splice(index, 1);
    await this.saveHarnesses();

    this.logger.log(`Deleted test harness: ${id}`);
  }

  async addTestSuite(harnessId: string, suiteId: string): Promise<TestHarnessEntity> {
    await this.loadHarnesses();
    const harness = await this.findOne(harnessId);
    
    if (!harness.testSuiteIds.includes(suiteId)) {
      harness.testSuiteIds.push(suiteId);
      harness.updatedAt = new Date();
      await this.saveHarnesses();
      this.logger.log(`Added test suite ${suiteId} to harness ${harnessId}`);
    }

    return harness;
  }

  async removeTestSuite(harnessId: string, suiteId: string): Promise<TestHarnessEntity> {
    await this.loadHarnesses();
    const harness = await this.findOne(harnessId);
    
    const index = harness.testSuiteIds.indexOf(suiteId);
    if (index > -1) {
      harness.testSuiteIds.splice(index, 1);
      harness.updatedAt = new Date();
      await this.saveHarnesses();
      this.logger.log(`Removed test suite ${suiteId} from harness ${harnessId}`);
    }

    return harness;
  }

  async assignToApplication(harnessId: string, applicationId: string): Promise<TestHarnessEntity> {
    await this.loadHarnesses();
    const harness = await this.findOne(harnessId);
    
    if (!harness.applicationIds.includes(applicationId)) {
      harness.applicationIds.push(applicationId);
      harness.updatedAt = new Date();
      await this.saveHarnesses();
      this.logger.log(`Assigned harness ${harnessId} to application ${applicationId}`);
    }

    return harness;
  }

  async unassignFromApplication(harnessId: string, applicationId: string): Promise<TestHarnessEntity> {
    await this.loadHarnesses();
    const harness = await this.findOne(harnessId);
    
    const index = harness.applicationIds.indexOf(applicationId);
    if (index > -1) {
      harness.applicationIds.splice(index, 1);
      harness.updatedAt = new Date();
      await this.saveHarnesses();
      this.logger.log(`Unassigned harness ${harnessId} from application ${applicationId}`);
    }

    return harness;
  }

  async findByApplication(applicationId: string): Promise<TestHarnessEntity[]> {
    await this.loadHarnesses();
    return this.harnesses.filter(h => h.applicationIds.includes(applicationId));
  }

  async findByTestSuite(suiteId: string): Promise<TestHarnessEntity[]> {
    await this.loadHarnesses();
    return this.harnesses.filter(h => h.testSuiteIds.includes(suiteId));
  }

  async getUsedInBatteries(harnessId: string): Promise<any[]> {
    await this.loadHarnesses();
    const harness = await this.findOne(harnessId);
    if (!harness) {
      return [];
    }

    // Read batteries file to find which batteries use this harness
    const batteriesFile = path.join(process.cwd(), 'data', 'test-batteries.json');
    try {
      const data = await fs.readFile(batteriesFile, 'utf-8');
      if (!data || data.trim() === '') {
        return [];
      }
      const batteries = JSON.parse(data);
      return batteries
        .filter((b: any) => b.harnessIds && b.harnessIds.includes(harnessId))
        .map((b: any) => ({
          id: b.id,
          name: b.name,
        }));
    } catch (err) {
      this.logger.error('Error getting batteries for harness:', err);
      return [];
    }
  }

  async getAssignedApplications(harnessId: string): Promise<any[]> {
    await this.loadHarnesses();
    const harness = await this.findOne(harnessId);
    if (!harness) {
      return [];
    }

    // Read applications file to get application details
    const applicationsFile = path.join(process.cwd(), 'data', 'applications.json');
    try {
      const data = await fs.readFile(applicationsFile, 'utf-8');
      if (!data || data.trim() === '') {
        return [];
      }
      const applications = JSON.parse(data);
      return applications
        .filter((app: any) => harness.applicationIds && harness.applicationIds.includes(app.id))
        .map((app: any) => ({
          id: app.id,
          name: app.name,
        }));
    } catch (err) {
      this.logger.error('Error getting applications for harness:', err);
      return [];
    }
  }
}

