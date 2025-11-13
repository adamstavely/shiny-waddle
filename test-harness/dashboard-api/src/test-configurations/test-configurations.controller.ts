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
import { TestConfigurationsService } from './test-configurations.service';
import {
  CreateTestConfigurationDto,
  CreateRLSCLSConfigurationDto,
  CreateNetworkPolicyConfigurationDto,
  CreateDLPConfigurationDto,
  CreateIdentityLifecycleConfigurationDto,
  CreateAPIGatewayConfigurationDto,
} from './dto/create-test-configuration.dto';
import { TestConfigurationEntity, TestConfigurationType } from './entities/test-configuration.entity';

@Controller('api/test-configurations')
export class TestConfigurationsController {
  private readonly logger = new Logger(TestConfigurationsController.name);

  constructor(private readonly configurationsService: TestConfigurationsService) {}

  @Get()
  async findAll(@Query('type') type?: TestConfigurationType): Promise<TestConfigurationEntity[]> {
    this.logger.log(`Listing test configurations${type ? ` of type ${type}` : ''}`);
    return this.configurationsService.findAll(type);
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<TestConfigurationEntity> {
    this.logger.log(`Getting test configuration: ${id}`);
    return this.configurationsService.findOne(id);
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(
    @Body(ValidationPipe) dto: CreateTestConfigurationDto,
  ): Promise<TestConfigurationEntity> {
    this.logger.log(`Creating test configuration: ${dto.name} (${dto.type})`);
    return this.configurationsService.create(dto);
  }

  @Put(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: Partial<CreateTestConfigurationDto>,
  ): Promise<TestConfigurationEntity> {
    this.logger.log(`Updating test configuration: ${id}`);
    return this.configurationsService.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async delete(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting test configuration: ${id}`);
    await this.configurationsService.delete(id);
  }

  @Patch(':id/enable')
  @HttpCode(HttpStatus.OK)
  async enable(@Param('id') id: string): Promise<TestConfigurationEntity> {
    this.logger.log(`Enabling test configuration: ${id}`);
    return this.configurationsService.enable(id);
  }

  @Patch(':id/disable')
  @HttpCode(HttpStatus.OK)
  async disable(@Param('id') id: string): Promise<TestConfigurationEntity> {
    this.logger.log(`Disabling test configuration: ${id}`);
    return this.configurationsService.disable(id);
  }

  @Post(':id/duplicate')
  @HttpCode(HttpStatus.CREATED)
  async duplicate(
    @Param('id') id: string,
    @Body() body?: { name?: string },
  ): Promise<TestConfigurationEntity> {
    this.logger.log(`Duplicating test configuration: ${id}`);
    return this.configurationsService.duplicate(id, body?.name);
  }

  @Post(':id/test')
  @HttpCode(HttpStatus.OK)
  async testConfiguration(@Param('id') id: string): Promise<any> {
    this.logger.log(`Testing configuration: ${id}`);
    return this.configurationsService.testConfiguration(id);
  }

  @Get(':id/applications')
  async getApplicationsUsingConfig(@Param('id') id: string): Promise<any[]> {
    this.logger.log(`Getting applications using test configuration: ${id}`);
    return this.configurationsService.findApplicationsUsingConfig(id);
  }
}

