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
} from '@nestjs/common';
import { TestSuitesService } from './test-suites.service';
import { CreateTestSuiteDto } from './dto/create-test-suite.dto';
import { UpdateTestSuiteDto } from './dto/update-test-suite.dto';
import { TestSuiteEntity } from './entities/test-suite.entity';

@Controller('api/test-suites')
export class TestSuitesController {
  private readonly logger = new Logger(TestSuitesController.name);

  constructor(private readonly testSuitesService: TestSuitesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) dto: CreateTestSuiteDto,
  ): Promise<TestSuiteEntity> {
    this.logger.log(`Creating test suite: ${dto.name}`);
    return this.testSuitesService.create(dto);
  }

  @Get()
  async findAll(
    @Query('applicationId') applicationId?: string,
    @Query('team') team?: string,
  ): Promise<TestSuiteEntity[]> {
    this.logger.log(`Listing test suites${applicationId ? ` for application ${applicationId}` : ''}${team ? ` for team ${team}` : ''}`);
    if (applicationId) {
      return this.testSuitesService.findByApplication(applicationId);
    }
    if (team) {
      return this.testSuitesService.findByTeam(team);
    }
    return this.testSuitesService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestSuiteEntity> {
    this.logger.log(`Getting test suite: ${id}`);
    return this.testSuitesService.findOne(id);
  }

  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateTestSuiteDto,
  ): Promise<TestSuiteEntity> {
    this.logger.log(`Updating test suite: ${id}`);
    return this.testSuitesService.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test suite: ${id}`);
    await this.testSuitesService.delete(id);
  }

  @Patch(':id/enable')
  @HttpCode(HttpStatus.OK)
  async enable(@Param('id') id: string): Promise<TestSuiteEntity> {
    this.logger.log(`Enabling test suite: ${id}`);
    return this.testSuitesService.enable(id);
  }

  @Patch(':id/disable')
  @HttpCode(HttpStatus.OK)
  async disable(@Param('id') id: string): Promise<TestSuiteEntity> {
    this.logger.log(`Disabling test suite: ${id}`);
    return this.testSuitesService.disable(id);
  }
}

