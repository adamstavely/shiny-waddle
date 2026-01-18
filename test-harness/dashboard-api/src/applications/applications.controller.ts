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
import { ToggleValidatorDto } from './dto/toggle-validator.dto';
import { BulkToggleDto } from './dto/bulk-toggle.dto';
import { Application } from './entities/application.entity';
import { AccessControlGuard, RequirePermission, Permission } from '../security/guards/access-control.guard';
import { Request as ExpressRequest } from 'express';
import { Public } from '../auth/decorators/public.decorator';

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

  @Public()
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

  @Public()
  @Get('issues')
  async getAllIssues(
    @Query('limit') limit?: string,
    @Query('priority') priority?: string,
  ): Promise<any[]> {
    return this.applicationsService.getAllIssues(
      limit ? parseInt(limit) : undefined,
      priority,
    );
  }

  @Public()
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

  @Get(':id/runs')
  async getRuns(
    @Param('id') id: string,
    @Query('limit') limit?: string,
  ): Promise<any[]> {
    return this.applicationsService.getRuns(id, limit ? parseInt(limit) : undefined);
  }

  @Public()
  @Get(':id/issues')
  async getIssues(
    @Param('id') id: string,
    @Query('limit') limit?: string,
    @Query('priority') priority?: string,
  ): Promise<any[]> {
    return this.applicationsService.getIssues(
      id,
      limit ? parseInt(limit) : undefined,
      priority,
    );
  }

  @Get(':id/compliance-score')
  async getComplianceScore(@Param('id') id: string): Promise<{ score: number }> {
    return this.applicationsService.getComplianceScore(id);
  }

  @Post(':id/test')
  @HttpCode(HttpStatus.OK)
  async updateLastTest(@Param('id') id: string): Promise<Application> {
    return this.applicationsService.updateLastTestAt(id, new Date());
  }


  /**
   * Get application infrastructure
   * NEW: Infrastructure is now part of Application entity
   */
  @Get(':id/infrastructure')
  async getInfrastructure(@Param('id') id: string): Promise<any> {
    const app = await this.applicationsService.findOne(id);
    return app.infrastructure || {};
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


  @Get(':id/validators/status')
  @RequirePermission(Permission.READ_APPLICATIONS)
  async getValidatorStatus(@Param('id') id: string) {
    return this.applicationsService.getValidatorStatus(id);
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

