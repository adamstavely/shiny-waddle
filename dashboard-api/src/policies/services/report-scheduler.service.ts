import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
// Note: @nestjs/schedule needs to be installed for cron jobs
// For now, using manual scheduling
// import { Cron, CronExpression } from '@nestjs/schedule';
import { AISummaryService } from './ai-summary.service';
import { CacheService } from './cache.service';

export interface ScheduledReport {
  id: string;
  name: string;
  type: 'executive' | 'detailed' | 'compliance';
  schedule: 'daily' | 'weekly' | 'monthly';
  recipients: string[];
  enabled: boolean;
  lastRun?: Date;
  nextRun: Date;
  templateId?: string;
}

@Injectable()
export class ReportSchedulerService {
  private readonly logger = new Logger(ReportSchedulerService.name);
  private readonly reports: Map<string, ScheduledReport> = new Map();

  constructor(
    private readonly aiSummaryService: AISummaryService,
    private readonly cacheService: CacheService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Create a scheduled report
   */
  async createScheduledReport(report: Omit<ScheduledReport, 'id' | 'nextRun'>): Promise<ScheduledReport> {
    const id = `report-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const nextRun = this.calculateNextRun(report.schedule);

    const scheduledReport: ScheduledReport = {
      ...report,
      id,
      nextRun,
    };

    this.reports.set(id, scheduledReport);
    this.logger.log(`Created scheduled report: ${id} (${report.schedule})`);

    return scheduledReport;
  }

  /**
   * Get all scheduled reports
   */
  async getAllReports(): Promise<ScheduledReport[]> {
    return Array.from(this.reports.values());
  }

  /**
   * Get a specific scheduled report
   */
  async getReport(id: string): Promise<ScheduledReport | null> {
    return this.reports.get(id) || null;
  }

  /**
   * Update a scheduled report
   */
  async updateReport(id: string, updates: Partial<ScheduledReport>): Promise<ScheduledReport> {
    const report = this.reports.get(id);
    if (!report) {
      throw new Error(`Report ${id} not found`);
    }

    const updated = {
      ...report,
      ...updates,
      nextRun: updates.schedule ? this.calculateNextRun(updates.schedule) : report.nextRun,
    };

    this.reports.set(id, updated);
    this.logger.log(`Updated scheduled report: ${id}`);

    return updated;
  }

  /**
   * Delete a scheduled report
   */
  async deleteReport(id: string): Promise<void> {
    if (this.reports.delete(id)) {
      this.logger.log(`Deleted scheduled report: ${id}`);
    }
  }

  /**
   * Generate and send a report
   */
  async generateAndSendReport(reportId: string): Promise<void> {
    const report = this.reports.get(reportId);
    if (!report || !report.enabled) {
      return;
    }

    try {
      this.logger.log(`Generating report: ${reportId}`);

      const endDate = new Date();
      const startDate = this.getStartDateForSchedule(report.schedule);

      let summary: any;
      if (report.type === 'executive') {
        summary = await this.aiSummaryService.generateExecutiveSummary(startDate, endDate);
      } else if (report.type === 'detailed') {
        summary = await this.aiSummaryService.generateDetailedSummary(startDate, endDate);
      } else {
        summary = await this.aiSummaryService.generateComplianceSummary();
      }

      // In production, this would send emails
      this.logger.log(`Report generated for ${reportId}. Would send to: ${report.recipients.join(', ')}`);

      // Update last run and next run
      report.lastRun = new Date();
      report.nextRun = this.calculateNextRun(report.schedule);
      this.reports.set(reportId, report);

      this.logger.log(`Report ${reportId} completed. Next run: ${report.nextRun.toISOString()}`);
    } catch (error) {
      this.logger.error(`Error generating report ${reportId}:`, error);
      throw error;
    }
  }

  /**
   * Daily report generation (runs at 8 AM)
   * Note: Requires @nestjs/schedule to be installed and ScheduleModule imported
   * For now, this can be called manually or via a cron job setup
   */
  async handleDailyReports() {
    this.logger.log('Running daily scheduled reports');
    await this.runScheduledReports('daily');
  }

  /**
   * Weekly report generation (runs on Monday at 8 AM)
   */
  async handleWeeklyReports() {
    this.logger.log('Running weekly scheduled reports');
    await this.runScheduledReports('weekly');
  }

  /**
   * Monthly report generation (runs on the 1st at 8 AM)
   */
  async handleMonthlyReports() {
    this.logger.log('Running monthly scheduled reports');
    await this.runScheduledReports('monthly');
  }

  /**
   * Run all reports for a given schedule
   */
  private async runScheduledReports(schedule: 'daily' | 'weekly' | 'monthly'): Promise<void> {
    const now = new Date();
    const reportsToRun = Array.from(this.reports.values()).filter(
      report => report.enabled && report.schedule === schedule && report.nextRun <= now
    );

    this.logger.log(`Found ${reportsToRun.length} ${schedule} reports to run`);

    for (const report of reportsToRun) {
      try {
        await this.generateAndSendReport(report.id);
      } catch (error) {
        this.logger.error(`Failed to generate report ${report.id}:`, error);
      }
    }
  }

  /**
   * Calculate next run time based on schedule
   */
  private calculateNextRun(schedule: 'daily' | 'weekly' | 'monthly'): Date {
    const now = new Date();
    const next = new Date(now);

    switch (schedule) {
      case 'daily':
        next.setDate(next.getDate() + 1);
        next.setHours(8, 0, 0, 0);
        break;
      case 'weekly':
        const daysUntilMonday = (8 - next.getDay()) % 7 || 7;
        next.setDate(next.getDate() + daysUntilMonday);
        next.setHours(8, 0, 0, 0);
        break;
      case 'monthly':
        next.setMonth(next.getMonth() + 1, 1);
        next.setHours(8, 0, 0, 0);
        break;
    }

    return next;
  }

  /**
   * Get start date for schedule type
   */
  private getStartDateForSchedule(schedule: 'daily' | 'weekly' | 'monthly'): Date {
    const endDate = new Date();
    const startDate = new Date(endDate);

    switch (schedule) {
      case 'daily':
        startDate.setDate(startDate.getDate() - 1);
        break;
      case 'weekly':
        startDate.setDate(startDate.getDate() - 7);
        break;
      case 'monthly':
        startDate.setMonth(startDate.getMonth() - 1);
        break;
    }

    return startDate;
  }
}
