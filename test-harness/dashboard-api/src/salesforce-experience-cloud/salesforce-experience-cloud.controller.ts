import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  HttpStatus,
  ValidationPipe,
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
  constructor(private readonly service: SalesforceExperienceCloudService) {}

  @Get()
  async getSummary() {
    const [configs, results] = await Promise.all([
      this.service.findAllConfigs(),
      this.service.findAllResults(),
    ]);
    return {
      configs: configs.length,
      results: results.length,
    };
  }

  // Configs
  @Post('configs')
  @HttpCode(HttpStatus.CREATED)
  async createConfig(
    @Body(ValidationPipe) dto: CreateSalesforceExperienceCloudConfigDto,
  ): Promise<SalesforceExperienceCloudConfigEntity> {
    return this.service.createConfig(dto);
  }

  @Get('configs')
  async findAllConfigs(): Promise<SalesforceExperienceCloudConfigEntity[]> {
    return this.service.findAllConfigs();
  }

  @Get('configs/:id')
  async findOneConfig(@Param('id') id: string): Promise<SalesforceExperienceCloudConfigEntity> {
    return this.service.findOneConfig(id);
  }

  @Patch('configs/:id')
  async updateConfig(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: UpdateSalesforceExperienceCloudConfigDto,
  ): Promise<SalesforceExperienceCloudConfigEntity> {
    return this.service.updateConfig(id, dto);
  }

  @Delete('configs/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeConfig(@Param('id') id: string): Promise<void> {
    return this.service.removeConfig(id);
  }

  // Tests
  @Post('tests/guest-access')
  @HttpCode(HttpStatus.CREATED)
  async runGuestAccessTest(
    @Body(ValidationPipe) dto: RunGuestAccessTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runGuestAccessTest(dto);
  }

  @Post('tests/authenticated-access')
  @HttpCode(HttpStatus.CREATED)
  async runAuthenticatedAccessTest(
    @Body(ValidationPipe) dto: RunAuthenticatedAccessTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runAuthenticatedAccessTest(dto);
  }

  @Post('tests/graphql')
  @HttpCode(HttpStatus.CREATED)
  async runGraphQLTest(
    @Body(ValidationPipe) dto: RunGraphQLTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runGraphQLTest(dto);
  }

  @Post('tests/self-registration')
  @HttpCode(HttpStatus.CREATED)
  async runSelfRegistrationTest(
    @Body(ValidationPipe) dto: RunSelfRegistrationTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runSelfRegistrationTest(dto);
  }

  @Post('tests/record-lists')
  @HttpCode(HttpStatus.CREATED)
  async runRecordListTest(
    @Body(ValidationPipe) dto: RunRecordListTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runRecordListTest(dto);
  }

  @Post('tests/home-urls')
  @HttpCode(HttpStatus.CREATED)
  async runHomeURLTest(
    @Body(ValidationPipe) dto: RunHomeURLTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runHomeURLTest(dto);
  }

  @Post('tests/object-access')
  @HttpCode(HttpStatus.CREATED)
  async runObjectAccessTest(
    @Body(ValidationPipe) dto: RunObjectAccessTestDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.runObjectAccessTest(dto);
  }

  @Post('tests/full-audit')
  @HttpCode(HttpStatus.CREATED)
  async runFullAudit(
    @Body(ValidationPipe) dto: RunFullAuditDto,
  ): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    return this.service.runFullAudit(dto);
  }

  // Results
  @Get('results')
  async findAllResults(@Param('configId') configId?: string): Promise<SalesforceExperienceCloudTestResultEntity[]> {
    return this.service.findAllResults(configId);
  }

  @Get('results/:id')
  async findOneResult(@Param('id') id: string): Promise<SalesforceExperienceCloudTestResultEntity> {
    return this.service.findOneResult(id);
  }

  @Delete('results/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async removeResult(@Param('id') id: string): Promise<void> {
    return this.service.removeResult(id);
  }
}
