import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Query,
  HttpCode,
  HttpStatus,
  ValidationPipe,
} from '@nestjs/common';
import { HistoryService } from './history.service';
import { CreateTestExecutionDto, CreateAuditLogDto, CreateActivityDto } from './dto/create-history.dto';
import {
  TestExecutionEntity,
  AuditLogEntity,
  ActivityEntity,
} from './entities/history.entity';

@Controller('api/history')
export class HistoryController {
  constructor(private readonly historyService: HistoryService) {}

  // Test Executions
  @Post('executions')
  @HttpCode(HttpStatus.CREATED)
  async createTestExecution(
    @Body(ValidationPipe) dto: CreateTestExecutionDto,
  ): Promise<TestExecutionEntity> {
    return this.historyService.createTestExecution(dto);
  }

  @Get('executions')
  async findAllTestExecutions(
    @Query('application') application?: string,
    @Query('team') team?: string,
    @Query('status') status?: string,
    @Query('dateFrom') dateFrom?: string,
    @Query('dateTo') dateTo?: string,
  ): Promise<TestExecutionEntity[]> {
    return this.historyService.findAllTestExecutions(application, team, status, dateFrom, dateTo);
  }

  @Get('executions/:id')
  async findOneTestExecution(@Param('id') id: string): Promise<TestExecutionEntity> {
    return this.historyService.findOneTestExecution(id);
  }

  @Get('executions/:id1/compare/:id2')
  async compareExecutions(
    @Param('id1') id1: string,
    @Param('id2') id2: string,
  ) {
    return this.historyService.compareExecutions(id1, id2);
  }

  // Audit Logs
  @Post('audit-logs')
  @HttpCode(HttpStatus.CREATED)
  async createAuditLog(
    @Body(ValidationPipe) dto: CreateAuditLogDto,
  ): Promise<AuditLogEntity> {
    return this.historyService.createAuditLog(dto);
  }

  @Get('audit-logs')
  async findAllAuditLogs(
    @Query('type') type?: string,
    @Query('application') application?: string,
    @Query('team') team?: string,
    @Query('dateFrom') dateFrom?: string,
    @Query('dateTo') dateTo?: string,
  ): Promise<AuditLogEntity[]> {
    return this.historyService.findAllAuditLogs(type, application, team, dateFrom, dateTo);
  }

  @Get('audit-logs/:id')
  async findOneAuditLog(@Param('id') id: string): Promise<AuditLogEntity> {
    return this.historyService.findOneAuditLog(id);
  }

  // Activities
  @Post('activities')
  @HttpCode(HttpStatus.CREATED)
  async createActivity(
    @Body(ValidationPipe) dto: CreateActivityDto,
  ): Promise<ActivityEntity> {
    return this.historyService.createActivity(dto);
  }

  @Get('activities')
  async findAllActivities(
    @Query('type') type?: string,
    @Query('application') application?: string,
    @Query('team') team?: string,
    @Query('dateFrom') dateFrom?: string,
    @Query('dateTo') dateTo?: string,
  ): Promise<ActivityEntity[]> {
    return this.historyService.findAllActivities(type, application, team, dateFrom, dateTo);
  }

  @Get('activities/:id')
  async findOneActivity(@Param('id') id: string): Promise<ActivityEntity> {
    return this.historyService.findOneActivity(id);
  }
}

