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
import { TestBatteriesService } from './test-batteries.service';
import { CreateTestBatteryDto } from './dto/create-test-battery.dto';
import { UpdateTestBatteryDto } from './dto/update-test-battery.dto';
import { TestBatteryEntity } from './entities/test-battery.entity';
import { Public } from '../auth/decorators/public.decorator';

@Controller('api/v1/test-batteries')
export class TestBatteriesController {
  private readonly logger = new Logger(TestBatteriesController.name);

  constructor(private readonly testBatteriesService: TestBatteriesService) {}

  @Public()
  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) dto: CreateTestBatteryDto,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Creating test battery: ${dto.name}`);
    return this.testBatteriesService.create(dto);
  }

  @Public()
  @Get()
  async findAll(
    @Query('domain') domain?: string,
  ): Promise<TestBatteryEntity[]> {
    this.logger.log(`Listing all test batteries${domain ? ` for domain ${domain}` : ''}`);
    const batteries = await this.testBatteriesService.findAll();
    
    // Filter by domain if provided (batteries that contain harnesses with this domain)
    if (domain) {
      // We need to check if any harness in the battery has this domain
      // This requires fetching harnesses, so we'll filter in the service if needed
      // For now, return all and let the service handle it if domain filtering is needed
      return batteries.filter(battery => {
        // Domain filtering for batteries would require checking harness domains
        // This is a simplified version - in practice, you'd need to fetch harnesses
        return true; // Return all for now, can be enhanced later
      });
    }
    
    return batteries;
  }

  @Public()
  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestBatteryEntity> {
    this.logger.log(`Getting test battery: ${id}`);
    return this.testBatteriesService.findOne(id);
  }

  @Public()
  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateTestBatteryDto,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Updating test battery: ${id}`);
    return this.testBatteriesService.update(id, dto);
  }

  @Public()
  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test battery: ${id}`);
    await this.testBatteriesService.delete(id);
  }

  @Public()
  @Post(':id/harnesses')
  @HttpCode(HttpStatus.OK)
  async addHarness(
    @Param('id') id: string,
    @Body('harnessId') harnessId: string,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Adding harness ${harnessId} to battery ${id}`);
    return this.testBatteriesService.addHarness(id, harnessId);
  }

  @Public()
  @Delete(':id/harnesses/:harnessId')
  @HttpCode(HttpStatus.OK)
  async removeHarness(
    @Param('id') id: string,
    @Param('harnessId') harnessId: string,
  ): Promise<TestBatteryEntity> {
    this.logger.log(`Removing harness ${harnessId} from battery ${id}`);
    return this.testBatteriesService.removeHarness(id, harnessId);
  }

  @Public()
  @Get(':id/assigned-applications')
  @HttpCode(HttpStatus.OK)
  async getAssignedApplications(@Param('id') id: string): Promise<any[]> {
    this.logger.log(`Getting applications using battery: ${id}`);
    return this.testBatteriesService.getAssignedApplications(id);
  }
}

