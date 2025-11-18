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
  Query,
  ValidationPipe,
} from '@nestjs/common';
import { PoliciesService } from './policies.service';
import { CreatePolicyDto, PolicyType, PolicyStatus } from './dto/create-policy.dto';
import { UpdatePolicyDto } from './dto/update-policy.dto';
import { Policy, PolicyVersion } from './entities/policy.entity';

@Controller('api/v1/policies')
export class PoliciesController {
  constructor(private readonly policiesService: PoliciesService) {}

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body(ValidationPipe) createPolicyDto: CreatePolicyDto): Promise<Policy> {
    return this.policiesService.create(createPolicyDto);
  }

  @Get()
  async findAll(
    @Query('type') type?: PolicyType,
    @Query('status') status?: PolicyStatus,
    @Query('applicationId') applicationId?: string,
  ): Promise<Policy[]> {
    return this.policiesService.findAll(type, status, applicationId);
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<Policy> {
    return this.policiesService.findOne(id);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) updatePolicyDto: UpdatePolicyDto,
  ): Promise<Policy> {
    return this.policiesService.update(id, updatePolicyDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string): Promise<void> {
    return this.policiesService.remove(id);
  }

  @Get(':id/versions')
  async getVersions(@Param('id') id: string): Promise<PolicyVersion[]> {
    return this.policiesService.getVersions(id);
  }

  @Post(':id/versions')
  async addVersion(
    @Param('id') id: string,
    @Body(ValidationPipe) version: PolicyVersion,
  ): Promise<Policy> {
    return this.policiesService.addVersion(id, version);
  }

  @Get(':id/compare/:version1/:version2')
  async compareVersions(
    @Param('id') id: string,
    @Param('version1') version1: string,
    @Param('version2') version2: string,
  ): Promise<any> {
    return this.policiesService.compareVersions(id, version1, version2);
  }

  @Post(':id/deploy')
  @HttpCode(HttpStatus.OK)
  async deploy(
    @Param('id') id: string,
    @Body('version') version?: string,
  ): Promise<Policy> {
    return this.policiesService.deploy(id, version);
  }

  @Post(':id/rollback')
  @HttpCode(HttpStatus.OK)
  async rollback(
    @Param('id') id: string,
    @Body('version') version: string,
  ): Promise<Policy> {
    return this.policiesService.rollback(id, version);
  }

  @Get(':id/audit')
  async getAuditLogs(@Param('id') id: string): Promise<any[]> {
    return this.policiesService.getAuditLogs(id);
  }

  @Get(':id/impact-analysis')
  async analyzeImpact(
    @Param('id') id: string,
    @Query('version') version?: string,
  ): Promise<any> {
    return this.policiesService.analyzeImpact(id, version);
  }

  @Post(':id/test')
  @HttpCode(HttpStatus.OK)
  async testPolicy(
    @Param('id') id: string,
    @Body() testData: any,
  ): Promise<any> {
    return this.policiesService.testPolicy(id, testData);
  }

  @Get(':id/tests')
  async getTestsUsingPolicy(@Param('id') id: string): Promise<any[]> {
    return this.policiesService.findTestsUsingPolicy(id);
  }

  // Domain-specific configuration endpoints
  @Get('domain-configs/:domain')
  async getDomainConfig(@Param('domain') domain: string): Promise<any> {
    return this.policiesService.getDomainConfig(domain);
  }

  @Post('domain-configs/:domain')
  @HttpCode(HttpStatus.OK)
  async saveDomainConfig(
    @Param('domain') domain: string,
    @Body() config: any,
  ): Promise<any> {
    await this.policiesService.saveDomainConfig(domain, config);
    return { message: 'Domain configuration saved successfully' };
  }

  @Get('domain-configs')
  async getAllDomainConfigs(): Promise<Record<string, any>> {
    return this.policiesService.getAllDomainConfigs();
  }
}

