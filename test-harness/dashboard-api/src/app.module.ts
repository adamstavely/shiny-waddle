import { Module } from '@nestjs/common';
import { DashboardModule } from './dashboard/dashboard.module';
import { ApplicationsModule } from './applications/applications.module';
import { ValidatorsModule } from './validators/validators.module';
import { ValidationTargetsModule } from './validation-targets/validation-targets.module';
import { PoliciesModule } from './policies/policies.module';
import { ViolationsModule } from './violations/violations.module';
import { HistoryModule } from './history/history.module';
import { ApiSecurityModule } from './api-security/api-security.module';
import { ReportsModule } from './reports/reports.module';
import { DistributedSystemsModule } from './distributed-systems/distributed-systems.module';
import { CICDModule } from './cicd/cicd.module';
import { TicketingModule } from './ticketing/ticketing.module';
import { SLAModule } from './sla/sla.module';
import { RemediationModule } from './remediation/remediation.module';
import { RemediationTrackingModule } from './remediation-tracking/remediation-tracking.module';
import { ComplianceModule } from './compliance/compliance.module';
import { UnifiedFindingsModule } from './unified-findings/unified-findings.module';
import { IntegrationsModule } from './integrations/integrations.module';
import { ScheduledReportsModule } from './scheduled-reports/scheduled-reports.module';
import { SecurityModule } from './security/security.module';
import { AppController } from './app.controller';

@Module({
  imports: [DashboardModule, ApplicationsModule, ValidatorsModule, ValidationTargetsModule, PoliciesModule, ViolationsModule, HistoryModule, ApiSecurityModule, ReportsModule, DistributedSystemsModule, CICDModule, TicketingModule, SLAModule, RemediationModule, RemediationTrackingModule, ComplianceModule, UnifiedFindingsModule, IntegrationsModule, ScheduledReportsModule, SecurityModule],
  controllers: [AppController],
})
export class AppModule {}
