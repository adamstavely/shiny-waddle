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
  Request,
  UseGuards,
} from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { CreateApplicationDto, ApplicationStatus, ApplicationType } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { AssignTestConfigurationsDto } from './dto/assign-test-configurations.dto';
import { ToggleTestConfigDto } from './dto/toggle-test-config.dto';
import { ToggleValidatorDto } from './dto/toggle-validator.dto';
import { BulkToggleDto } from './dto/bulk-toggle.dto';
import { Application } from './entities/application.entity';
import { AccessControlGuard, RequirePermission, Permission } from '../security/guards/access-control.guard';
import { Request as ExpressRequest } from 'express';

@Controller('api/v1/applications')
@UseGuards(AccessControlGuard)
export class ApplicationsController {
  constructor(private readonly applicationsService: ApplicationsService) {}

  private getUserFromRequest(req: ExpressRequest): { userId?: string; username?: string } {
    const user = (req as any).user;
    return {
      userId: user?.id || user?.userId,
      username: user?.username || user?.email,
    };
  }

  @Post()
  @HttpCode(HttpStatus.CREATED)
  async create(@Body(ValidationPipe) createApplicationDto: CreateApplicationDto): Promise<Application> {
    return this.applicationsService.create(createApplicationDto);
  }

  @Get()
  async findAll(
    @Query('team') team?: string,
    @Query('status') status?: ApplicationStatus,
    @Query('type') type?: ApplicationType,
  ): Promise<Application[]> {
    if (team) {
      return this.applicationsService.findByTeam(team);
    }
    if (status) {
      return this.applicationsService.findByStatus(status);
    }
    if (type) {
      return this.applicationsService.findByType(type);
    }
    return this.applicationsService.findAll();
  }

  @Get(':id')
  async findOne(@Param('id') id: string): Promise<Application> {
    return this.applicationsService.findOne(id);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body(ValidationPipe) updateApplicationDto: UpdateApplicationDto,
  ): Promise<Application> {
    return this.applicationsService.update(id, updateApplicationDto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  async remove(@Param('id') id: string): Promise<void> {
    return this.applicationsService.remove(id);
  }

  @Get(':id/test-harnesses')
  async getTestHarnesses(@Param('id') id: string): Promise<any[]> {
    return this.applicationsService.getAssignedTestHarnesses(id);
  }

  @Get(':id/test-batteries')
  async getTestBatteries(@Param('id') id: string): Promise<any[]> {
    return this.applicationsService.getAssignedTestBatteries(id);
  }

  @Post(':id/test')
  @HttpCode(HttpStatus.OK)
  async updateLastTest(@Param('id') id: string): Promise<Application> {
    return this.applicationsService.updateLastTestAt(id, new Date());
  }

  @Post(':id/test-configurations')
  @HttpCode(HttpStatus.OK)
  async assignTestConfigurations(
    @Param('id') id: string,
    @Body(ValidationPipe) body: AssignTestConfigurationsDto,
  ): Promise<Application> {
    return this.applicationsService.assignTestConfigurations(id, body.testConfigurationIds);
  }

  @Get(':id/test-configurations')
  async getTestConfigurations(
    @Param('id') id: string,
    @Query('expand') expand?: string,
  ): Promise<string[] | any[]> {
    return this.applicationsService.getTestConfigurations(id, expand === 'true');
  }

  @Post(':id/run-tests')
  @HttpCode(HttpStatus.OK)
  async runTests(
    @Param('id') id: string,
    @Query('buildId') buildId?: string,
    @Query('runId') runId?: string,
    @Query('commitSha') commitSha?: string,
    @Query('branch') branch?: string,
  ): Promise<{
    status: 'passed' | 'failed' | 'partial';
    totalTests: number;
    passed: number;
    failed: number;
    results: any[];
  }> {
    return this.applicationsService.runTests(id, { buildId, runId, commitSha, branch });
  }

  @Patch(':id/test-configurations/:configId/toggle')
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async toggleTestConfiguration(
    @Param('id') id: string,
    @Param('configId') configId: string,
    @Body(ValidationPipe) dto: ToggleTestConfigDto,
    @Request() req: ExpressRequest,
  ): Promise<Application> {
    const user = this.getUserFromRequest(req);
    return this.applicationsService.toggleTestConfiguration(
      id,
      configId,
      dto.enabled,
      dto.reason,
      user.userId,
      user.username,
    );
  }

  @Patch(':id/validators/:validatorId/toggle')
  @RequirePermission(Permission.MANAGE_APPLICATION_VALIDATORS)
  async toggleValidator(
    @Param('id') id: string,
    @Param('validatorId') validatorId: string,
    @Body(ValidationPipe) dto: ToggleValidatorDto,
    @Request() req: ExpressRequest,
  ): Promise<Application> {
    const user = this.getUserFromRequest(req);
    return this.applicationsService.toggleValidator(
      id,
      validatorId,
      dto.enabled,
      dto.reason,
      user.userId,
      user.username,
    );
  }

  @Get(':id/test-configurations/status')
  @RequirePermission(Permission.READ_APPLICATIONS)
  async getTestConfigurationStatus(@Param('id') id: string) {
    return this.applicationsService.getTestConfigurationStatus(id);
  }

  @Get(':id/validators/status')
  @RequirePermission(Permission.READ_APPLICATIONS)
  async getValidatorStatus(@Param('id') id: string) {
    return this.applicationsService.getValidatorStatus(id);
  }

  @Patch(':id/test-configurations/bulk-toggle')
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async bulkToggleTestConfigurations(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: BulkToggleDto,
    @Request() req: ExpressRequest,
  ): Promise<Application> {
    const user = this.getUserFromRequest(req);
    return this.applicationsService.bulkToggleTestConfigurations(
      id,
      dto.items,
      user.userId,
      user.username,
    );
  }

  @Patch(':id/validators/bulk-toggle')
  @RequirePermission(Permission.MANAGE_APPLICATION_VALIDATORS)
  async bulkToggleValidators(
    @Param('id') id: string,
    @Body(ValidationPipe) dto: BulkToggleDto,
    @Request() req: ExpressRequest,
  ): Promise<Application> {
    const user = this.getUserFromRequest(req);
    return this.applicationsService.bulkToggleValidators(
      id,
      dto.items,
      user.userId,
      user.username,
    );
  }

  @Delete(':id/test-configurations/:configId/override')
  @RequirePermission(Permission.MANAGE_APPLICATION_TESTS)
  async removeTestConfigurationOverride(
    @Param('id') id: string,
    @Param('configId') configId: string,
    @Request() req: ExpressRequest,
  ): Promise<Application> {
    const user = this.getUserFromRequest(req);
    return this.applicationsService.removeTestConfigurationOverride(
      id,
      configId,
      user.userId,
      user.username,
    );
  }

  @Delete(':id/validators/:validatorId/override')
  @RequirePermission(Permission.MANAGE_APPLICATION_VALIDATORS)
  async removeValidatorOverride(
    @Param('id') id: string,
    @Param('validatorId') validatorId: string,
    @Request() req: ExpressRequest,
  ): Promise<Application> {
    const user = this.getUserFromRequest(req);
    return this.applicationsService.removeValidatorOverride(
      id,
      validatorId,
      user.userId,
      user.username,
    );
  }
}

