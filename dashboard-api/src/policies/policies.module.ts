import { Module } from '@nestjs/common';
// Note: Uncomment when @nestjs/schedule is installed
// import { ScheduleModule } from '@nestjs/schedule';
import { PoliciesController } from './policies.controller';
import { PoliciesService } from './policies.service';
import { PolicyVersioningService } from './services/policy-versioning.service';
import { PolicyTemplatesService } from './services/policy-templates.service';
import { PolicyDiffService } from './services/policy-diff.service';
import { SystemStateComparisonService } from './services/system-state-comparison.service';
import { DataTagComparisonService } from './services/data-tag-comparison.service';
import { GapAnalysisService } from './services/gap-analysis.service';
import { AISummaryService } from './services/ai-summary.service';
import { LLMIntegrationService } from './services/llm-integration.service';
import { CacheService } from './services/cache.service';
import { ReportSchedulerService } from './services/report-scheduler.service';
import { AutomationService } from './services/automation.service';
import { PolicyNotificationsService } from './services/policy-notifications.service';
import { CollaborationService } from './services/collaboration.service';

@Module({
  // imports: [ScheduleModule.forRoot()], // Uncomment when @nestjs/schedule is installed
  controllers: [PoliciesController],
  providers: [
    PoliciesService,
    PolicyVersioningService,
    PolicyTemplatesService,
    PolicyDiffService,
    SystemStateComparisonService,
    DataTagComparisonService,
    GapAnalysisService,
    AISummaryService,
    LLMIntegrationService,
    CacheService,
    ReportSchedulerService,
    AutomationService,
    PolicyNotificationsService,
    CollaborationService,
  ],
  exports: [
    PoliciesService,
    PolicyVersioningService,
    PolicyTemplatesService,
    PolicyDiffService,
    SystemStateComparisonService,
    DataTagComparisonService,
    GapAnalysisService,
    AISummaryService,
    LLMIntegrationService,
    CacheService,
    ReportSchedulerService,
    AutomationService,
    PolicyNotificationsService,
    CollaborationService,
  ],
})
export class PoliciesModule {}

