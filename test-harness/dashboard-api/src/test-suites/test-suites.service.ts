import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { TestSuiteEntity, TestSuiteStatus } from './entities/test-suite.entity';
import { CreateTestSuiteDto } from './dto/create-test-suite.dto';
import { UpdateTestSuiteDto } from './dto/update-test-suite.dto';
import { parseTypeScriptTestSuite, convertJSONToTypeScript } from './test-suite-converter';
import { getDomainFromTestType } from '../../../core/domain-mapping';
import { TestType } from '../../../core/types';

@Injectable()
export class TestSuitesService {
  private readonly logger = new Logger(TestSuitesService.name);
  private readonly suitesFile = path.join(process.cwd(), 'data', 'test-suites.json');
  private readonly projectRoot = process.cwd().includes('dashboard-api') 
    ? path.join(process.cwd(), '..')
    : process.cwd();
  private suites: TestSuiteEntity[] = [];
  private filesystemSuites: Map<string, TestSuiteEntity> = new Map(); // keyed by sourcePath

  constructor() {
    this.loadSuites().catch(err => {
      this.logger.error('Error loading test suites on startup:', err);
    });
    this.discoverFilesystemSuites().catch(err => {
      this.logger.error('Error discovering filesystem test suites on startup:', err);
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

    // Validate testType
    const validTestTypes = [
      'access-control',
      'dataset-health',
      'rls-cls',
      'network-policy',
      'dlp',
      'api-gateway',
      'distributed-systems',
      'api-security',
      'data-pipeline',
      'data-contract',
      'salesforce-config',
      'salesforce-security',
      'elastic-config',
      'elastic-security',
      'k8s-security',
      'k8s-workload',
      'idp-compliance',
    ];
    if (!validTestTypes.includes(dto.testType)) {
      throw new BadRequestException(
        `Invalid testType "${dto.testType}". Valid types are: ${validTestTypes.join(', ')}`
      );
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
      testType: dto.testType,
      domain,
      testTypes: dto.testTypes || [dto.testType], // Set testTypes to match testType for backward compatibility
      enabled: dto.enabled !== undefined ? dto.enabled : true,
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
    await this.discoverFilesystemSuites();
    
    // Combine JSON-based suites with filesystem suites
    const allSuites = [...this.suites];
    const filesystemArray = Array.from(this.filesystemSuites.values());
    
    // Merge filesystem suites, avoiding duplicates by name+application
    for (const fsSuite of filesystemArray) {
      const existing = allSuites.find(
        s => s.name === fsSuite.name && s.applicationId === fsSuite.applicationId
      );
      if (!existing) {
        allSuites.push(fsSuite);
      }
    }
    
    return allSuites;
  }

  /**
   * Discover test suite files from filesystem
   */
  async discoverFilesystemSuites(): Promise<void> {
    try {
      this.filesystemSuites.clear();
      
      // Scan tests/ directory for configuration test suites
      const testsDir = path.join(this.projectRoot, 'tests');
      try {
        const testFiles = await fs.readdir(testsDir);
        for (const file of testFiles) {
          if (file.endsWith('.ts') && !file.endsWith('.d.ts') && file !== 'test-suite-loader.ts') {
            const filePath = path.join(testsDir, file);
            await this.processTestSuiteFile(filePath, 'tests');
          }
        }
      } catch (error: any) {
        if (error.code !== 'ENOENT') {
          this.logger.warn(`Could not read tests directory: ${error.message}`);
        }
      }

      // Scan services/test-suites/ directory for class-based test suites
      const servicesTestSuitesDir = path.join(this.projectRoot, 'services', 'test-suites');
      try {
        const suiteFiles = await fs.readdir(servicesTestSuitesDir);
        for (const file of suiteFiles) {
          if (file.endsWith('.ts') && !file.endsWith('.d.ts') && file !== 'base-test-suite.ts') {
            const filePath = path.join(servicesTestSuitesDir, file);
            await this.processTestSuiteFile(filePath, 'services/test-suites');
          }
        }
      } catch (error: any) {
        if (error.code !== 'ENOENT') {
          this.logger.warn(`Could not read services/test-suites directory: ${error.message}`);
        }
      }
    } catch (error) {
      this.logger.error('Error discovering filesystem test suites:', error);
    }
  }

  /**
   * Process a single test suite file
   */
  private async processTestSuiteFile(filePath: string, baseDir: string): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const parsed = parseTypeScriptTestSuite(content, filePath);
      
      if (parsed) {
        // Generate ID from file path (consistent hash)
        const relativePath = path.relative(this.projectRoot, filePath);
        const id = `fs-${Buffer.from(relativePath).toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32)}`;
        
        const suite: TestSuiteEntity = {
          id,
          name: parsed.name,
          applicationId: parsed.application,
          application: parsed.application,
          team: parsed.team,
          description: parsed.description,
          status: 'pending',
          testCount: 0,
          score: 0,
          testTypes: parsed.testTypes,
          enabled: true,
          createdAt: new Date(), // Use file mtime if available
          updatedAt: new Date(),
          sourceType: 'typescript',
          sourcePath: relativePath,
        };

        // Try to get file stats for better timestamps
        try {
          const stats = await fs.stat(filePath);
          suite.createdAt = stats.birthtime;
          suite.updatedAt = stats.mtime;
        } catch {
          // Ignore stat errors
        }

        this.filesystemSuites.set(relativePath, suite);
      }
    } catch (error) {
      this.logger.warn(`Error processing test suite file ${filePath}:`, error);
    }
  }

  /**
   * Get source file content for a test suite
   */
  async getTestSuiteSource(id: string): Promise<{ content: string; sourceType: string; sourcePath?: string }> {
    const suite = await this.findOne(id);
    
    if (suite.sourceType === 'typescript' && suite.sourcePath) {
      const fullPath = path.join(this.projectRoot, suite.sourcePath);
      try {
        const content = await fs.readFile(fullPath, 'utf-8');
        return {
          content,
          sourceType: 'typescript',
          sourcePath: suite.sourcePath,
        };
      } catch (error: any) {
        throw new NotFoundException(`Source file not found: ${suite.sourcePath}`);
      }
    } else {
      // For JSON-based suites, return the JSON representation
      const jsonContent = JSON.stringify(suite, null, 2);
      return {
        content: jsonContent,
        sourceType: 'json',
      };
    }
  }

  /**
   * Update source file for a test suite
   */
  async updateTestSuiteSource(id: string, content: string): Promise<void> {
    const suite = await this.findOne(id);
    
    if (suite.sourceType === 'typescript' && suite.sourcePath) {
      const fullPath = path.join(this.projectRoot, suite.sourcePath);
      try {
        await fs.writeFile(fullPath, content, 'utf-8');
        // Re-discover to update metadata
        await this.discoverFilesystemSuites();
        this.logger.log(`Updated test suite source file: ${suite.sourcePath}`);
      } catch (error: any) {
        throw new BadRequestException(`Failed to update source file: ${error.message}`);
      }
    } else {
      // For JSON-based suites, we can't update the source directly via this method
      // They should be updated via the regular update() method
      throw new BadRequestException('Cannot update source for JSON-based test suites. Use the regular update endpoint.');
    }
  }

  /**
   * Extract full TestSuite configuration from TypeScript source
   */
  async extractTestSuiteConfig(id: string): Promise<TestSuite | null> {
    const suite = await this.findOne(id);
    
    if (suite.sourceType === 'typescript' && suite.sourcePath) {
      const fullPath = path.join(this.projectRoot, suite.sourcePath);
      try {
        const content = await fs.readFile(fullPath, 'utf-8');
        const { extractTestSuiteFromContent } = await import('./test-suite-converter');
        return extractTestSuiteFromContent(content, suite.sourcePath);
      } catch (error: any) {
        this.logger.error(`Error extracting config from ${suite.sourcePath}:`, error);
        throw new BadRequestException(`Failed to extract configuration: ${error.message}`);
      }
    }
    
    return null;
  }

  async findOne(id: string): Promise<TestSuiteEntity> {
    await this.loadSuites();
    await this.discoverFilesystemSuites();
    
    // Check JSON-based suites first
    let suite = this.suites.find(s => s.id === id);
    
    // If not found, check filesystem suites
    if (!suite) {
      suite = Array.from(this.filesystemSuites.values()).find(s => s.id === id);
    }
    
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

    // Check for duplicate name if name is being changed
    if (dto.name && dto.name !== existing.name) {
      const duplicate = this.suites.find(
        s => s.name === dto.name && s.applicationId === (dto.applicationId || existing.applicationId) && s.id !== id
      );
      if (duplicate) {
        throw new BadRequestException(`Test suite with name "${dto.name}" for application "${dto.applicationId || existing.applicationId}" already exists`);
      }
    }

    // Auto-update domain if testType changes
    let domain = existing.domain;
    if (dto.testType && dto.testType !== existing.testType) {
      domain = getDomainFromTestType(dto.testType as TestType);
    } else if (dto.domain) {
      // Validate provided domain matches testType
      const expectedDomain = getDomainFromTestType((dto.testType || existing.testType) as TestType);
      if (dto.domain !== expectedDomain) {
        throw new BadRequestException(
          `Domain "${dto.domain}" does not match testType "${dto.testType || existing.testType}" (expected: "${expectedDomain}")`
        );
      }
      domain = dto.domain;
    }

    const updated: TestSuiteEntity = {
      ...existing,
      ...dto,
      id: existing.id, // Don't allow ID changes
      testType: dto.testType || existing.testType, // Keep existing if not provided
      domain,
      testTypes: dto.testTypes || (dto.testType ? [dto.testType] : existing.testTypes), // Update testTypes if testType changed
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
    await this.discoverFilesystemSuites();
    
    const jsonSuites = this.suites.filter(s => s.applicationId === applicationId);
    const fsSuites = Array.from(this.filesystemSuites.values()).filter(s => s.applicationId === applicationId);
    
    return [...jsonSuites, ...fsSuites];
  }

  async findByTeam(team: string): Promise<TestSuiteEntity[]> {
    await this.loadSuites();
    await this.discoverFilesystemSuites();
    
    const jsonSuites = this.suites.filter(s => s.team === team);
    const fsSuites = Array.from(this.filesystemSuites.values()).filter(s => s.team === team);
    
    return [...jsonSuites, ...fsSuites];
  }

  async getUsedInHarnesses(suiteId: string): Promise<any[]> {
    await this.loadSuites();
    const suite = await this.findOne(suiteId);
    if (!suite) {
      return [];
    }

    // Import TestHarnessesService dynamically to avoid circular dependency
    const { TestHarnessesService } = await import('../test-harnesses/test-harnesses.service');
    const { TestHarnessesModule } = await import('../test-harnesses/test-harnesses.module');
    // For now, we'll need to inject this properly, but for the reverse lookup we can query directly
    // This is a simplified version - in production you'd inject the service properly
    try {
      const harnessesModule = await import('../test-harnesses/test-harnesses.module');
      // We'll need to get the service instance, but for now let's use a simpler approach
      // Read the harnesses file directly or use a shared service
      const harnessesFile = path.join(process.cwd(), 'data', 'test-harnesses.json');
      let harnesses: any[] = [];
      try {
        const data = await fs.readFile(harnessesFile, 'utf-8');
        if (data && data.trim()) {
          harnesses = JSON.parse(data);
        }
      } catch (err) {
        // File doesn't exist or is invalid
      }
      
      return harnesses.filter((h: any) => 
        h.testSuiteIds && h.testSuiteIds.includes(suiteId)
      ).map((h: any) => ({
        id: h.id,
        name: h.name,
      }));
    } catch (err) {
      this.logger.error('Error getting harnesses for suite:', err);
      return [];
    }
  }
}

