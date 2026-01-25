import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Logger,
} from '@nestjs/common';
import { SalesforceExperienceCloudService } from './salesforce-experience-cloud.service';
import {
  CreateSalesforceExperienceCloudConfigDto,
  UpdateSalesforceExperienceCloudConfigDto,
  RunGuestAccessTestDto,
  RunAuthenticatedAccessTestDto,
  RunGraphQLTestDto,
  RunSelfRegistrationTestDto,
  RunRecordListTestDto,
  RunHomeURLTestDto,
  RunObjectAccessTestDto,
  RunFullAuditDto,
} from './dto/salesforce-experience-cloud.dto';
import {
  SalesforceExperienceCloudConfigEntity,
  SalesforceExperienceCloudTestResultEntity,
} from './entities/salesforce-experience-cloud.entity';

@Controller('api/salesforce-experience-cloud')
export class SalesforceExperienceCloudController {
  private readonly logger = new Logger(SalesforceExperienceCloudController.name);

  constructor(private readonly salesforceExperienceCloudService: SalesforceExperienceCloudService) {}

  @Get()
  async getSummary() {
    return this.salesforceExperienceCloudService.getSummary();
  }

  // Configuration Management
  @Post('configs')
  @HttpCode(HttpStatus.CREATED)
  async createConfig(
    @Body(ValidationPipe) dto: CreateSalesforceExperienceCloudConfigDto,
  ): Promise<SalesforceExperienceCloudConfigEntity> {
    this.logger.log(`Creating Salesforce Experience Cloud config: ${dto.name}`);
    return this.salesforceExperienceCloudService.createConfig(dto);
  }

  @Get('configs')
  async findAllConfigs(): Promise<SalesforceExperienceCloudConfigEntity[]> {
    return this.salesforceExperienceCloudService.findAllConfigs();
  }

  @Get('configs/:id')
  async findOneConfig(@Param('id') id: string): Promise<SalesforceExperienceCloudConfigEntity> {
    return this.salesforceExperienceCloudService.findOneConfig(id);
  }

  @Patch('configs/:id')
  async updateConfig(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateSalesforceExperienceCloudConfigDto,
  ): Promise<SalesforceExperienceCloudConfigEntity> {
    this.logger.log(`Updating Salesforce Experience Cloud config: ${id}`);
    return this.salesforceExperienceCloudService.updateConfig(id, dto);
  }

  @Delete('configs/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeConfig(@Param('id') id: string): Promise<void> {
    this.logger.log(`Deleting Salesforce Experience Cloud config: ${id}`);
    return this.salesforceExperienceCloudService.removeConfig(id);
  }

  // Test Execution Endpoints
  @Post('tests/guest-access')
  @HttpCode(HttpStatus.CREATED)
  async runGuestAccessTest(
    @Body(ValidationPipe) dto: RunGuestAccessTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running guest access test for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runGuestAccessTest(dto);
  }

  @Post('tests/authenticated-access')
  @HttpCode(HttpStatus.CREATED)
  async runAuthenticatedAccessTest(
    @Body(ValidationPipe) dto: RunAuthenticatedAccessTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running authenticated access test for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runAuthenticatedAccessTest(dto);
  }

  @Post('tests/graphql')
  @HttpCode(HttpStatus.CREATED)
  async runGraphQLTest(
    @Body(ValidationPipe) dto: RunGraphQLTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running GraphQL test for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runGraphQLTest(dto);
  }

  @Post('tests/self-registration')
  @HttpCode(HttpStatus.CREATED)
  async runSelfRegistrationTest(
    @Body(ValidationPipe) dto: RunSelfRegistrationTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running self-registration test for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runSelfRegistrationTest(dto);
  }

  @Post('tests/record-lists')
  @HttpCode(HttpStatus.CREATED)
  async runRecordListTest(
    @Body(ValidationPipe) dto: RunRecordListTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running record list test for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runRecordListTest(dto);
  }

  @Post('tests/home-urls')
  @HttpCode(HttpStatus.CREATED)
  async runHomeURLTest(
    @Body(ValidationPipe) dto: RunHomeURLTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running home URL test for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runHomeURLTest(dto);
  }

  @Post('tests/object-access')
  @HttpCode(HttpStatus.CREATED)
  async runObjectAccessTest(
    @Body(ValidationPipe) dto: RunObjectAccessTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    this.logger.log(`Running object access test for config: ${dto.configId} with objects: ${dto.objects.join(', ')}`);
    return this.salesforceExperienceCloudService.runObjectAccessTest(dto);
  }

  @Post('tests/full-audit')
  @HttpCode(HttpStatus.CREATED)
  async runFullAudit(
    @Body(ValidationPipe) dto: RunFullAuditDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    this.logger.log(`Running full audit for config: ${dto.configId}`);
    return this.salesforceExperienceCloudService.runFullAudit(dto);
  }

  // Results Management
  @Get('results')
  async findAllResults(
    @Query('configId') configId?: string,
  ): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    return this.salesforceExperienceCloudService.findAllResults(configId);
  }

  @Get('results/:id')
  async findOneResult(@Param('id') id: string): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.salesforceExperienceCloudService.findOneResult(id);
  }
}
