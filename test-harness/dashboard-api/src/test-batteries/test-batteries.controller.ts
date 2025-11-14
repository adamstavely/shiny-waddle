import {
  Controller,
  Get,
  Post,
  Put,
  Delete,
  Body,
  Param,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { TestBatteriesService } from './test-batteries.service';
import { CreateTestBatteryDto } from './dto/create-test-battery.dto';
import { UpdateTestBatteryDto } from './dto/update-test-battery.dto';
import { TestBatteryEntity } from './entities/test-battery.entity';

@Controller('api/test-batteries')
export class TestBatteriesController {
  private readonly logger = new Logger(TestBatteriesController.name);

  constructor(private readonly testBatteriesService: TestBatteriesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) dto: CreateTestBatteryDto,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Creating test battery: ${dto.name}`);
    return this.testBatteriesService.create(dto);
  }

  @Get()
  async findAll(): Promise<TestBatteryEntity[]> {
    this.logger.log('Listing all test batteries');
    return this.testBatteriesService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestBatteryEntity> {
    this.logger.log(`Getting test battery: ${id}`);
    return this.testBatteriesService.findOne(id);
  }

  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateTestBatteryDto,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Updating test battery: ${id}`);
    return this.testBatteriesService.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test battery: ${id}`);
    await this.testBatteriesService.delete(id);
  }

  @Post(':id/harnesses')
  @HttpCode(HttpStatus.OK)
  async addHarness(
    @Param('id') id: string,
    @Body('harnessId') harnessId: string,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Adding harness ${harnessId} to battery ${id}`);
    return this.testBatteriesService.addHarness(id, harnessId);
  }

  @Delete(':id/harnesses/:harnessId')
  @HttpCode(HttpStatus.OK)
  async removeHarness(
    @Param('id') id: string,
    @Param('harnessId') harnessId: string,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Removing harness ${harnessId} from battery ${id}`);
    return this.testBatteriesService.removeHarness(id, harnessId);
  }
}

