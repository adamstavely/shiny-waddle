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
import { ApplicationsService } from './applications.service';
import { CreateApplicationDto, ApplicationStatus, ApplicationType } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { AssignTestConfigurationsDto } from './dto/assign-test-configurations.dto';
import { Application } from './entities/application.entity';

@Controller('api/applications')
export class ApplicationsController {
  constructor(private readonly applicationsService: ApplicationsService) {}

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
}

