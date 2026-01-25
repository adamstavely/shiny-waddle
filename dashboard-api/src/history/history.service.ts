import { Injectable, NotFoundException } from '@nestjs/common';
import { CreateTestExecutionDto, CreateAuditLogDto, CreateActivityDto } from './dto/create-history.dto';
import {
  TestExecutionEntity,
  AuditLogEntity,
  ActivityEntity,
} from './entities/history.entity';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class HistoryService {
  private readonly executionsFile = path.join(process.cwd(), '..', 'data', 'test-executions.json');
  private readonly auditLogsFile = path.join(process.cwd(), '..', 'data', 'audit-logs.json');
  private readonly activitiesFile = path.join(process.cwd(), '..', 'data', 'activities.json');
  
  private testExecutions: TestExecutionEntity[] = [];
  private auditLogs: AuditLogEntity[] = [];
  private activities: ActivityEntity[] = [];

  constructor() {
    this.loadData().catch(err => {
      console.error('Error loading history data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    await Promise.all([
      this.loadExecutions(),
      this.loadAuditLogs(),
      this.loadActivities(),
    ]);
  }

  private async loadExecutions(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.executionsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.executionsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.testExecutions = (Array.isArray(parsed) ? parsed : []).map((e: any) => ({
          ...e,
          timestamp: new Date(e.timestamp),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.testExecutions = [];
          await this.saveExecutions();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading test executions:', error);
      this.testExecutions = [];
    }
  }

  private async loadAuditLogs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.auditLogsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.auditLogsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.auditLogs = (Array.isArray(parsed) ? parsed : []).map((l: any) => ({
          ...l,
          timestamp: new Date(l.timestamp),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.auditLogs = [];
          await this.saveAuditLogs();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading audit logs:', error);
      this.auditLogs = [];
    }
  }

  private async loadActivities(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.activitiesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.activitiesFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.activities = (Array.isArray(parsed) ? parsed : []).map((a: any) => ({
          ...a,
          timestamp: new Date(a.timestamp),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.activities = [];
          await this.saveActivities();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading activities:', error);
      this.activities = [];
    }
  }

  private async saveExecutions() {
    try {
      await fs.mkdir(path.dirname(this.executionsFile), { recursive: true });
      await fs.writeFile(
        this.executionsFile,
        JSON.stringify(this.testExecutions, null, 2),
        'utf-8',
      );
    } catch (error) {
      console.error('Error saving test executions:', error);
      throw error;
    }
  }

  private async saveAuditLogs() {
    try {
      await fs.mkdir(path.dirname(this.auditLogsFile), { recursive: true });
      await fs.writeFile(
        this.auditLogsFile,
        JSON.stringify(this.auditLogs, null, 2),
        'utf-8',
      );
    } catch (error) {
      console.error('Error saving audit logs:', error);
      throw error;
    }
  }

  private async saveActivities() {
    try {
      await fs.mkdir(path.dirname(this.activitiesFile), { recursive: true });
      await fs.writeFile(
        this.activitiesFile,
        JSON.stringify(this.activities, null, 2),
        'utf-8',
      );
    } catch (error) {
      console.error('Error saving activities:', error);
      throw error;
    }
  }

  // Test Executions
  async createTestExecution(dto: CreateTestExecutionDto): Promise<TestExecutionEntity> {
    const execution: TestExecutionEntity = {
      id: uuidv4(),
      ...dto,
      timestamp: new Date(),
    };

    this.testExecutions.push(execution);
    await this.saveExecutions();

    // Also create an activity
    await this.createActivity({
      type: 'test-execution' as any,
      user: dto.metadata?.user || 'system',
      action: `completed test suite`,
      details: `${dto.suiteName} (${dto.score}% compliance)`,
      application: dto.application,
      team: dto.team,
      resourceId: execution.id,
      resourceType: 'test-execution',
    });

    return execution;
  }

  async findAllTestExecutions(
    application?: string,
    team?: string,
    status?: string,
    dateFrom?: string,
    dateTo?: string,
  ): Promise<TestExecutionEntity[]> {
    let filtered = [...this.testExecutions];

    if (application) {
      filtered = filtered.filter(e => e.application === application);
    }
    if (team) {
      filtered = filtered.filter(e => e.team === team);
    }
    if (status) {
      filtered = filtered.filter(e => e.status === status);
    }
    if (dateFrom) {
      const fromDate = new Date(dateFrom);
      filtered = filtered.filter(e => e.timestamp >= fromDate);
    }
    if (dateTo) {
      const toDate = new Date(dateTo);
      toDate.setHours(23, 59, 59, 999);
      filtered = filtered.filter(e => e.timestamp <= toDate);
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async findOneTestExecution(id: string): Promise<TestExecutionEntity> {
    const execution = this.testExecutions.find(e => e.id === id);
    if (!execution) {
      throw new NotFoundException(`Test execution with ID "${id}" not found`);
    }
    return execution;
  }

  // Audit Logs
  async createAuditLog(dto: CreateAuditLogDto): Promise<AuditLogEntity> {
    const log: AuditLogEntity = {
      id: uuidv4(),
      ...dto,
      timestamp: new Date(),
    };

    this.auditLogs.push(log);
    await this.saveAuditLogs();

    return log;
  }

  async findAllAuditLogs(
    type?: string,
    application?: string,
    team?: string,
    dateFrom?: string,
    dateTo?: string,
  ): Promise<AuditLogEntity[]> {
    let filtered = [...this.auditLogs];

    if (type) {
      filtered = filtered.filter(l => l.type === type);
    }
    if (application) {
      filtered = filtered.filter(l => l.application === application);
    }
    if (team) {
      filtered = filtered.filter(l => l.team === team);
    }
    if (dateFrom) {
      const fromDate = new Date(dateFrom);
      filtered = filtered.filter(l => l.timestamp >= fromDate);
    }
    if (dateTo) {
      const toDate = new Date(dateTo);
      toDate.setHours(23, 59, 59, 999);
      filtered = filtered.filter(l => l.timestamp <= toDate);
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async findOneAuditLog(id: string): Promise<AuditLogEntity> {
    const log = this.auditLogs.find(l => l.id === id);
    if (!log) {
      throw new NotFoundException(`Audit log with ID "${id}" not found`);
    }
    return log;
  }

  // Activities
  async createActivity(dto: CreateActivityDto): Promise<ActivityEntity> {
    const activity: ActivityEntity = {
      id: uuidv4(),
      ...dto,
      timestamp: new Date(),
    };

    this.activities.push(activity);
    await this.saveActivities();

    return activity;
  }

  async findAllActivities(
    type?: string,
    application?: string,
    team?: string,
    dateFrom?: string,
    dateTo?: string,
  ): Promise<ActivityEntity[]> {
    let filtered = [...this.activities];

    if (type) {
      filtered = filtered.filter(a => a.type === type);
    }
    if (application) {
      filtered = filtered.filter(a => a.application === application);
    }
    if (team) {
      filtered = filtered.filter(a => a.team === team);
    }
    if (dateFrom) {
      const fromDate = new Date(dateFrom);
      filtered = filtered.filter(a => a.timestamp >= fromDate);
    }
    if (dateTo) {
      const toDate = new Date(dateTo);
      toDate.setHours(23, 59, 59, 999);
      filtered = filtered.filter(a => a.timestamp <= toDate);
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async findOneActivity(id: string): Promise<ActivityEntity> {
    const activity = this.activities.find(a => a.id === id);
    if (!activity) {
      throw new NotFoundException(`Activity with ID "${id}" not found`);
    }
    return activity;
  }

  // Comparison
  async compareExecutions(id1: string, id2: string): Promise<{
    execution1: TestExecutionEntity;
    execution2: TestExecutionEntity;
    differences: any;
  }> {
    const exec1 = await this.findOneTestExecution(id1);
    const exec2 = await this.findOneTestExecution(id2);

    const differences = {
      score: exec2.score - exec1.score,
      testCount: exec2.testCount - exec1.testCount,
      passedCount: exec2.passedCount - exec1.passedCount,
      failedCount: exec2.failedCount - exec1.failedCount,
      duration: (exec2.duration || 0) - (exec1.duration || 0),
    };

    return {
      execution1: exec1,
      execution2: exec2,
      differences,
    };
  }
}

