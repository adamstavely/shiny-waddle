import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { TestHarnessesService } from './test-harnesses.service';
import { CreateTestHarnessDto } from './dto/create-test-harness.dto';
import { UpdateTestHarnessDto } from './dto/update-test-harness.dto';
import { TestHarnessEntity } from './entities/test-harness.entity';

@Controller('api/v1/test-harnesses')
export class TestHarnessesController {
  private readonly logger = new Logger(TestHarnessesController.name);

  constructor(private readonly testHarnessesService: TestHarnessesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) dto: CreateTestHarnessDto,
  ): Promise<TestHarnessEntity> {
    this.logger.log(`Creating test harness: ${dto.name}`);
    return this.testHarnessesService.create(dto);
  }

  @Get()
  async findAll(
    @Query('applicationId') applicationId?: string,
    @Query('suiteId') suiteId?: string,
    @Query('domain') domain?: string,
  ): Promise<TestHarnessEntity[]> {
    this.logger.log(`Listing test harnesses${applicationId ? ` for application ${applicationId}` : ''}${suiteId ? ` for suite ${suiteId}` : ''}${domain ? ` for domain ${domain}` : ''}`);
    let harnesses: TestHarnessEntity[];
    if (applicationId) {
      harnesses = await this.testHarnessesService.findByApplication(applicationId);
    } else if (suiteId) {
      harnesses = await this.testHarnessesService.findByTestSuite(suiteId);
    } else {
      harnesses = await this.testHarnessesService.findAll();
    }
    
    // Filter by domain if provided
    if (domain) {
      harnesses = harnesses.filter(h => h.domain === domain);
    }
    
    return harnesses;
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestHarnessEntity> {
    this.logger.log(`Getting test harness: ${id}`);
    return this.testHarnessesService.findOne(id);
  }

  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateTestHarnessDto,
  ): Promise<TestHarnessEntity> {
    this.logger.log(`Updating test harness: ${id}`);
    return this.testHarnessesService.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test harness: ${id}`);
    await this.testHarnessesService.delete(id);
  }

  @Post(':id/test-suites')
  @HttpCode(HttpStatus.OK)
  async addTestSuite(
    @Param('id') id: string,
    @Body('suiteId') suiteId: string,
  ): Promise<TestHarnessEntity> {
    this.logger.log(`Adding test suite ${suiteId} to harness ${id}`);
    return this.testHarnessesService.addTestSuite(id, suiteId);
  }

  @Delete(':id/test-suites/:suiteId')
  @HttpCode(HttpStatus.OK)
  async removeTestSuite(
    @Param('id') id: string,
    @Param('suiteId') suiteId: string,
  ): Promise<TestHarnessEntity> {
    this.logger.log(`Removing test suite ${suiteId} from harness ${id}`);
    return this.testHarnessesService.removeTestSuite(id, suiteId);
  }

  @Post(':id/applications')
  @HttpCode(HttpStatus.OK)
  async assignToApplication(
    @Param('id') id: string,
    @Body('applicationId') applicationId: string,
  ): Promise<TestHarnessEntity> {
    this.logger.log(`Assigning harness ${id} to application ${applicationId}`);
    return this.testHarnessesService.assignToApplication(id, applicationId);
  }

  @Delete(':id/applications/:appId')
  @HttpCode(HttpStatus.OK)
  async unassignFromApplication(
    @Param('id') id: string,
    @Param('appId') appId: string,
  ): Promise<TestHarnessEntity> {
    this.logger.log(`Unassigning harness ${id} from application ${appId}`);
    return this.testHarnessesService.unassignFromApplication(id, appId);
  }

  @Get(':id/used-in-batteries')
  @HttpCode(HttpStatus.OK)
  async getUsedInBatteries(@Param('id') id: string): Promise<any[]> {
    this.logger.log(`Getting batteries using harness: ${id}`);
    return this.testHarnessesService.getUsedInBatteries(id);
  }

  @Get(':id/assigned-applications')
  @HttpCode(HttpStatus.OK)
  async getAssignedApplications(@Param('id') id: string): Promise<any[]> {
    this.logger.log(`Getting applications assigned to harness: ${id}`);
    return this.testHarnessesService.getAssignedApplications(id);
  }
}

