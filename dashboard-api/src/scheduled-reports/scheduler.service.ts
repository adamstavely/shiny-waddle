import { Injectable } from '@nestjs/common';
import { ScheduledReport } from './entities/scheduled-report.entity';

@Injectable()
export class SchedulerService {
  private schedules: Map<string, ScheduledReport> = new Map();

  registerSchedule(report: ScheduledReport): void {
    this.schedules.set(report.id, report);
    console.log(`Registered schedule: ${report.name} (${report.id}) - Next run: ${report.nextRun}`);
  }

  unregisterSchedule(id: string): void {
    this.schedules.delete(id);
    console.log(`Unregistered schedule: ${id}`);
  }

  getSchedule(id: string): ScheduledReport | undefined {
    return this.schedules.get(id);
  }

  getAllSchedules(): ScheduledReport[] {
    return Array.from(this.schedules.values());
  }
}

