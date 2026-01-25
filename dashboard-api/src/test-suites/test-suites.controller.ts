import {
  Controller,
  Get,
  Post,
  Put,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { TestSuitesService } from './test-suites.service';
import { CreateTestSuiteDto } from './dto/create-test-suite.dto';
import { UpdateTestSuiteDto } from './dto/update-test-suite.dto';
import { TestSuiteEntity } from './entities/test-suite.entity';
import { Public } from '../auth/decorators/public.decorator';

@Controller('api/v1/test-suites')
export class TestSuitesController {
  private readonly logger = new Logger(TestSuitesController.name);

  constructor(private readonly testSuitesService: TestSuitesService) {}

  @Public()
  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) dto: CreateTestSuiteDto,
  ): Promise<TestSuiteEntity> {
    this.logger.log(`Creating test suite: ${dto.name}`);
    return this.testSuitesService.create(dto);
  }

  @Public()
  @Get()
  async findAll(
    @Query('applicationId') applicationId?: string,
    @Query('team') team?: string,
    @Query('domain') domain?: string,
  ): Promise<TestSuiteEntity[]> {
    this.logger.log(`Listing test suites${applicationId ? ` for application ${applicationId}` : ''}${team ? ` for team ${team}` : ''}${domain ? ` for domain ${domain}` : ''}`);
    let suites: TestSuiteEntity[];
    if (applicationId) {
      suites = await this.testSuitesService.findByApplication(applicationId);
    } else if (team) {
      suites = await this.testSuitesService.findByTeam(team);
    } else {
      suites = await this.testSuitesService.findAll();
    }
    
    // Filter by domain if provided
    if (domain) {
      suites = suites.filter(s => s.domain === domain);
    }
    
    return suites;
  }

  @Public()
  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestSuiteEntity> {
    this.logger.log(`Getting test suite: ${id}`);
    return this.testSuitesService.findOne(id);
  }

  @Public()
  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateTestSuiteDto,
  ): Promise<TestSuiteEntity> {
    this.logger.log(`Updating test suite: ${id}`);
    return this.testSuitesService.update(id, dto);
  }

  @Public()
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test suite: ${id}`);
    await this.testSuitesService.delete(id);
  }

  @Public()
  @Patch(':id/enable')
  @HttpCode(HttpStatus.OK)
  async enable(@Param('id') id: string): Promise<TestSuiteEntity> {
    this.logger.log(`Enabling test suite: ${id}`);
    return this.testSuitesService.enable(id);
  }

  @Public()
  @Patch(':id/disable')
  @HttpCode(HttpStatus.OK)
  async disable(@Param('id') id: string): Promise<TestSuiteEntity> {
    this.logger.log(`Disabling test suite: ${id}`);
    return this.testSuitesService.disable(id);
  }

  @Public()
  @Get('discover')
  @HttpCode(HttpStatus.OK)
  async discover(): Promise<{ message: string; count: number }> {
    this.logger.log('Triggering filesystem test suite discovery');
    await this.testSuitesService.discoverFilesystemSuites();
    const allSuites = await this.testSuitesService.findAll();
    const fsCount = allSuites.filter(s => s.sourceType === 'typescript').length;
    return {
      message: 'Filesystem test suites discovered',
      count: fsCount,
    };
  }

  @Public()
  @Get(':id/source')
  @HttpCode(HttpStatus.OK)
  async getSource(@Param('id') id: string): Promise<{ content: string; sourceType: string; sourcePath?: string }> {
    this.logger.log(`Getting source for test suite: ${id}`);
    return this.testSuitesService.getTestSuiteSource(id);
  }

  @Public()
  @Put(':id/source')
  @HttpCode(HttpStatus.OK)
  async updateSource(
    @Param('id') id: string,
    @Body() body: { content: string },
  ): Promise<{ message: string }> {
    this.logger.log(`Updating source for test suite: ${id}`);
    await this.testSuitesService.updateTestSuiteSource(id, body.content);
    return { message: 'Source file updated successfully' };
  }

  @Public()
  @Get(':id/extract-config')
  @HttpCode(HttpStatus.OK)
  async extractConfig(@Param('id') id: string): Promise<{ config: any }> {
    this.logger.log(`Extracting config for test suite: ${id}`);
    const config = await this.testSuitesService.extractTestSuiteConfig(id);
    if (!config) {
      throw new NotFoundException('Could not extract configuration from source file');
    }
    return { config };
  }

  @Public()
  @Get(':id/used-in-harnesses')
  @HttpCode(HttpStatus.OK)
  async getUsedInHarnesses(@Param('id') id: string): Promise<any[]> {
    this.logger.log(`Getting harnesses using test suite: ${id}`);
    return this.testSuitesService.getUsedInHarnesses(id);
  }

  @Public()
  @Post(':id/run')
  @HttpCode(HttpStatus.OK)
  async runTestSuite(@Param('id') id: string): Promise<{
    suiteId: string;
    suiteName: string;
    status: 'passed' | 'failed' | 'partial';
    totalTests: number;
    passed: number;
    failed: number;
    results: any[];
    timestamp: Date;
  }> {
    this.logger.log(`Running test suite: ${id}`);
    return this.testSuitesService.runTestSuite(id);
  }

  @Public()
  @Get(':id/results')
  @HttpCode(HttpStatus.OK)
  async getTestResults(@Param('id') id: string): Promise<{
    suiteId: string;
    lastRun?: Date;
    results: any[];
  }> {
    this.logger.log(`Getting test results for suite: ${id}`);
    return this.testSuitesService.getTestResults(id);
  }
}

