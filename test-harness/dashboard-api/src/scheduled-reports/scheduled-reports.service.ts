import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { ScheduledReport } from './entities/scheduled-report.entity';
import { CreateScheduledReportDto } from './dto/create-scheduled-report.dto';
import { UpdateScheduledReportDto } from './dto/update-scheduled-report.dto';
import { ReportsService } from '../reports/reports.service';
import { SchedulerService } from './scheduler.service';

@Injectable()
export class ScheduledReportsService implements OnModuleInit, OnModuleDestroy {
  private readonly dataDir = path.join(process.cwd(), '..', '..', 'data');
  private readonly dataFile = path.join(this.dataDir, 'scheduled-reports.json');
  private scheduler: NodeJS.Timeout | null = null;

  constructor(
    private readonly reportsService: ReportsService,
    private readonly schedulerService: SchedulerService,
  ) {}

  async onModuleInit() {
    await this.loadScheduledReports();
    this.startScheduler();
  }

  async onModuleDestroy() {
    if (this.scheduler) {
      clearInterval(this.scheduler);
    }
  }

  private async loadScheduledReports(): Promise<void> {
    try {
      await fs.mkdir(this.dataDir, { recursive: true });
      const data = await fs.readFile(this.dataFile, 'utf-8').catch(() => '[]');
      const reports: ScheduledReport[] = JSON.parse(data);
      
      // Register all enabled schedules
      for (const report of reports) {
        if (report.enabled) {
          this.schedulerService.registerSchedule(report);
        }
      }
    } catch (error) {
      console.error('Error loading scheduled reports:', error);
    }
  }

  private async saveScheduledReports(reports: ScheduledReport[]): Promise<void> {
    await fs.mkdir(this.dataDir, { recursive: true });
    await fs.writeFile(this.dataFile, JSON.stringify(reports, null, 2));
  }

  private startScheduler(): void {
    // Check every minute for scheduled reports that need to run
    this.scheduler = setInterval(async () => {
      await this.checkAndRunSchedules();
    }, 60000); // Check every minute
  }

  private async checkAndRunSchedules(): Promise<void> {
    const reports = await this.getAllScheduledReports();
    const now = new Date();

    for (const report of reports) {
      if (!report.enabled) continue;
      
      if (report.nextRun && new Date(report.nextRun) <= now) {
        await this.executeScheduledReport(report);
      }
    }
  }

  async executeScheduledReportNow(report: ScheduledReport): Promise<void> {
    await this.executeScheduledReport(report);
  }

  private async executeScheduledReport(report: ScheduledReport): Promise<void> {
    try {
      console.log(`Executing scheduled report: ${report.name} (${report.id})`);
      
      // Calculate date range
      let dateFrom: string | undefined;
      let dateTo: string | undefined;
      
      if (report.dateRange) {
        if (report.dateRange.type === 'relative' && report.dateRange.days) {
          const toDate = new Date();
          const fromDate = new Date();
          fromDate.setDate(fromDate.getDate() - report.dateRange.days);
          dateTo = toDate.toISOString().split('T')[0];
          dateFrom = fromDate.toISOString().split('T')[0];
        } else if (report.dateRange.type === 'absolute') {
          dateFrom = report.dateRange.from;
          dateTo = report.dateRange.to;
        }
      }

      // Generate report using ReportsService
      // Convert pdf/excel formats to html for now (can be enhanced later)
      const reportFormat = (report.format === 'pdf' || report.format === 'excel') 
        ? 'html' 
        : report.format as 'json' | 'html' | 'xml';
      
      const generateRequest = {
        name: `${report.name} - ${new Date().toLocaleDateString()}`,
        format: reportFormat,
        applicationIds: report.applicationIds,
        teamIds: report.teamIds,
        validatorIds: report.validatorIds,
        dateFrom,
        dateTo,
        includeCharts: report.includeCharts ?? true,
        includeDetails: report.includeDetails ?? true,
      };

      const generatedReport = await this.reportsService.generateReport(generateRequest);

      // Update schedule with last run and calculate next run
      report.lastRun = new Date();
      report.runCount = (report.runCount || 0) + 1;
      report.nextRun = this.calculateNextRun(report);
      report.lastError = undefined;

      await this.updateScheduledReport(report.id, report);

      // Handle delivery
      await this.deliverReport(report, generatedReport);

      console.log(`Successfully executed scheduled report: ${report.name}`);
    } catch (error: any) {
      console.error(`Error executing scheduled report ${report.name}:`, error);
      report.lastError = error.message;
      await this.updateScheduledReport(report.id, report);
    }
  }

  private async deliverReport(
    schedule: ScheduledReport,
    report: any,
  ): Promise<void> {
    switch (schedule.deliveryMethod) {
      case 'email':
        // TODO: Implement email delivery
        console.log(`Would send report to: ${schedule.recipients?.join(', ')}`);
        break;
      case 'webhook':
        if (schedule.webhookUrl) {
          // TODO: Implement webhook delivery
          console.log(`Would POST report to: ${schedule.webhookUrl}`);
        }
        break;
      case 'storage':
        // Report is already stored by ReportsService
        console.log(`Report stored: ${report.id}`);
        break;
    }
  }

  private calculateNextRun(report: ScheduledReport): Date {
    const now = new Date();
    const next = new Date(now);

    if (report.frequency === 'daily') {
      if (report.time) {
        const [hours, minutes] = report.time.split(':').map(Number);
        next.setHours(hours, minutes, 0, 0);
        if (next <= now) {
          next.setDate(next.getDate() + 1);
        }
      } else {
        next.setDate(next.getDate() + 1);
        next.setHours(0, 0, 0, 0);
      }
    } else if (report.frequency === 'weekly') {
      const dayOfWeek = report.dayOfWeek ?? 1; // Default to Monday
      const currentDay = now.getDay();
      let daysUntilNext = (dayOfWeek - currentDay + 7) % 7;
      if (daysUntilNext === 0) {
        daysUntilNext = 7; // Next week
      }
      next.setDate(next.getDate() + daysUntilNext);
      if (report.time) {
        const [hours, minutes] = report.time.split(':').map(Number);
        next.setHours(hours, minutes, 0, 0);
      } else {
        next.setHours(0, 0, 0, 0);
      }
    } else if (report.frequency === 'monthly') {
      const dayOfMonth = report.dayOfMonth ?? 1;
      next.setMonth(next.getMonth() + 1);
      next.setDate(dayOfMonth);
      if (report.time) {
        const [hours, minutes] = report.time.split(':').map(Number);
        next.setHours(hours, minutes, 0, 0);
      } else {
        next.setHours(0, 0, 0, 0);
      }
    } else if (report.frequency === 'custom' && report.cronExpression) {
      // Simple cron parsing (for production, use a library like node-cron)
      // For now, default to daily
      next.setDate(next.getDate() + 1);
    }

    return next;
  }

  async getAllScheduledReports(): Promise<ScheduledReport[]> {
    try {
      const data = await fs.readFile(this.dataFile, 'utf-8').catch(() => '[]');
      const reports: ScheduledReport[] = JSON.parse(data);
      return reports.map(r => ({
        ...r,
        lastRun: r.lastRun ? new Date(r.lastRun) : undefined,
        nextRun: new Date(r.nextRun),
        createdAt: new Date(r.createdAt),
        updatedAt: new Date(r.updatedAt),
      }));
    } catch (error) {
      console.error('Error loading scheduled reports:', error);
      return [];
    }
  }

  async getScheduledReportById(id: string): Promise<ScheduledReport | null> {
    const reports = await this.getAllScheduledReports();
    return reports.find(r => r.id === id) || null;
  }

  async createScheduledReport(dto: CreateScheduledReportDto): Promise<ScheduledReport> {
    const reports = await this.getAllScheduledReports();
    
    const report: ScheduledReport = {
      id: `scheduled-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      name: dto.name,
      enabled: dto.enabled ?? true,
      frequency: dto.frequency,
      cronExpression: dto.cronExpression,
      time: dto.time,
      dayOfWeek: dto.dayOfWeek,
      dayOfMonth: dto.dayOfMonth,
      format: dto.format,
      reportType: dto.reportType || 'custom',
      template: dto.template,
      applicationIds: dto.applicationIds,
      teamIds: dto.teamIds,
      validatorIds: dto.validatorIds,
      dateRange: dto.dateRange,
      includeCharts: dto.includeCharts ?? true,
      includeDetails: dto.includeDetails ?? true,
      includeTrends: dto.includeTrends,
      includeRiskScores: dto.includeRiskScores,
      recipients: dto.recipients,
      deliveryMethod: dto.deliveryMethod || 'storage',
      webhookUrl: dto.webhookUrl,
      lastRun: undefined,
      nextRun: this.calculateNextRun({
        frequency: dto.frequency,
        time: dto.time,
        dayOfWeek: dto.dayOfWeek,
        dayOfMonth: dto.dayOfMonth,
        cronExpression: dto.cronExpression,
      } as ScheduledReport),
      runCount: 0,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    reports.push(report);
    await this.saveScheduledReports(reports);

    if (report.enabled) {
      this.schedulerService.registerSchedule(report);
    }

    return report;
  }

  async updateScheduledReport(
    id: string,
    dto: UpdateScheduledReportDto | ScheduledReport,
  ): Promise<ScheduledReport> {
    const reports = await this.getAllScheduledReports();
    const index = reports.findIndex(r => r.id === id);
    
    if (index === -1) {
      throw new Error('Scheduled report not found');
    }

    const existing = reports[index];
    const wasEnabled = existing.enabled;

    // If it's already a ScheduledReport, use it directly; otherwise merge
    const updated: ScheduledReport = 'id' in dto && dto.id === id
      ? dto as ScheduledReport
      : {
          ...existing,
          ...dto,
          id: existing.id,
          updatedAt: new Date(),
          nextRun: dto.frequency || dto.time || dto.dayOfWeek || dto.dayOfMonth || dto.cronExpression
            ? this.calculateNextRun({ ...existing, ...dto } as ScheduledReport)
            : existing.nextRun,
        };

    reports[index] = updated;
    await this.saveScheduledReports(reports);

    // Re-register if enabled status changed
    if (wasEnabled !== updated.enabled) {
      if (updated.enabled) {
        this.schedulerService.registerSchedule(updated);
      } else {
        this.schedulerService.unregisterSchedule(id);
      }
    } else if (updated.enabled) {
      // Re-register if schedule changed
      this.schedulerService.registerSchedule(updated);
    }

    return updated;
  }

  async deleteScheduledReport(id: string): Promise<void> {
    const reports = await this.getAllScheduledReports();
    const filtered = reports.filter(r => r.id !== id);
    
    if (filtered.length === reports.length) {
      throw new Error('Scheduled report not found');
    }

    await this.saveScheduledReports(filtered);
    this.schedulerService.unregisterSchedule(id);
  }

  async toggleScheduledReport(id: string, enabled: boolean): Promise<ScheduledReport> {
    const report = await this.getScheduledReportById(id);
    if (!report) {
      throw new Error('Scheduled report not found');
    }

    return this.updateScheduledReport(id, { enabled });
  }
}

