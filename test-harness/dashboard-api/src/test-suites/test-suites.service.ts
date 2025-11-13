import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { TestSuiteEntity, TestSuiteStatus } from './entities/test-suite.entity';
import { CreateTestSuiteDto } from './dto/create-test-suite.dto';
import { UpdateTestSuiteDto } from './dto/update-test-suite.dto';

@Injectable()
export class TestSuitesService {
  private readonly logger = new Logger(TestSuitesService.name);
  private readonly suitesFile = path.join(process.cwd(), 'data', 'test-suites.json');
  private suites: TestSuiteEntity[] = [];

  constructor() {
    this.loadSuites().catch(err => {
      this.logger.error('Error loading test suites on startup:', err);
    });
  }

  private async loadSuites(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.suitesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.suitesFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.suites = [];
          await this.saveSuites();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Test suites file does not contain an array, initializing empty');
          this.suites = [];
          await this.saveSuites();
          return;
        }
        this.suites = parsed.map((s: any) => ({
          ...s,
          createdAt: s.createdAt ? new Date(s.createdAt) : new Date(),
          updatedAt: s.updatedAt ? new Date(s.updatedAt) : new Date(),
          lastRun: s.lastRun ? new Date(s.lastRun) : undefined,
          enabled: s.enabled !== undefined ? s.enabled : true,
          testCount: s.testCount || 0,
          score: s.score || 0,
          testTypes: s.testTypes || [],
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.suites = [];
          await this.saveSuites();
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error in test suites file, initializing empty:', readError.message);
          this.suites = [];
          await this.saveSuites();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading test suites:', error);
      this.suites = [];
    }
  }

  private async saveSuites(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.suitesFile), { recursive: true });
      await fs.writeFile(this.suitesFile, JSON.stringify(this.suites, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving test suites:', error);
      throw error;
    }
  }

  async create(dto: CreateTestSuiteDto): Promise<TestSuiteEntity> {
    await this.loadSuites();

    // Check for duplicate name
    const existing = this.suites.find(s => s.name === dto.name && s.applicationId === dto.applicationId);
    if (existing) {
      throw new BadRequestException(`Test suite with name "${dto.name}" for application "${dto.applicationId}" already exists`);
    }

    const now = new Date();
    const suite: TestSuiteEntity = {
      id: uuidv4(),
      name: dto.name,
      applicationId: dto.applicationId,
      team: dto.team,
      description: dto.description,
      status: dto.status || 'pending',
      testCount: dto.testCount || 0,
      score: dto.score || 0,
      testTypes: dto.testTypes || [],
      enabled: dto.enabled !== undefined ? dto.enabled : true,
      testConfigurationIds: dto.testConfigurationIds || [],
      createdAt: now,
      updatedAt: now,
    };

    this.suites.push(suite);
    await this.saveSuites();
    this.logger.log(`Created test suite: ${suite.id} (${suite.name})`);
    return suite;
  }

  async findAll(): Promise<TestSuiteEntity[]> {
    await this.loadSuites();
    return this.suites;
  }

  async findOne(id: string): Promise<TestSuiteEntity> {
    await this.loadSuites();
    const suite = this.suites.find(s => s.id === id);
    if (!suite) {
      throw new NotFoundException(`Test suite with ID ${id} not found`);
    }
    return suite;
  }

  async update(id: string, dto: UpdateTestSuiteDto): Promise<TestSuiteEntity> {
    await this.loadSuites();
    const index = this.suites.findIndex(s => s.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test suite with ID ${id} not found`);
    }

    const existing = this.suites[index];

    // Check for duplicate name if name is being changed
    if (dto.name && dto.name !== existing.name) {
      const duplicate = this.suites.find(
        s => s.name === dto.name && s.applicationId === (dto.applicationId || existing.applicationId) && s.id !== id
      );
      if (duplicate) {
        throw new BadRequestException(`Test suite with name "${dto.name}" for application "${dto.applicationId || existing.applicationId}" already exists`);
      }
    }

    const updated: TestSuiteEntity = {
      ...existing,
      ...dto,
      id: existing.id, // Don't allow ID changes
      updatedAt: new Date(),
    };

    this.suites[index] = updated;
    await this.saveSuites();
    this.logger.log(`Updated test suite: ${id}`);
    return updated;
  }

  async delete(id: string): Promise<void> {
    await this.loadSuites();
    const index = this.suites.findIndex(s => s.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test suite with ID ${id} not found`);
    }

    this.suites.splice(index, 1);
    await this.saveSuites();
    this.logger.log(`Deleted test suite: ${id}`);
  }

  async enable(id: string): Promise<TestSuiteEntity> {
    await this.loadSuites();
    const suite = await this.findOne(id);
    suite.enabled = true;
    suite.updatedAt = new Date();
    await this.saveSuites();
    this.logger.log(`Enabled test suite: ${id}`);
    return suite;
  }

  async disable(id: string): Promise<TestSuiteEntity> {
    await this.loadSuites();
    const suite = await this.findOne(id);
    suite.enabled = false;
    suite.updatedAt = new Date();
    await this.saveSuites();
    this.logger.log(`Disabled test suite: ${id}`);
    return suite;
  }

  async findByApplication(applicationId: string): Promise<TestSuiteEntity[]> {
    await this.loadSuites();
    return this.suites.filter(s => s.applicationId === applicationId);
  }

  async findByTeam(team: string): Promise<TestSuiteEntity[]> {
    await this.loadSuites();
    return this.suites.filter(s => s.team === team);
  }
}

