import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { VersionMiddleware } from './common/middleware/version.middleware';
import { HttpsRedirectMiddleware } from './common/middleware/https-redirect.middleware';
import { SanitizeMiddleware } from './common/middleware/sanitize.middleware';
import { DashboardModule } from './dashboard/dashboard.module';
import { ApplicationsModule } from './applications/applications.module';
import { ValidatorsModule } from './validators/validators.module';
import { ValidationTargetsModule } from './validation-targets/validation-targets.module';
import { PoliciesModule } from './policies/policies.module';
import { ViolationsModule } from './violations/violations.module';
import { HistoryModule } from './history/history.module';
import { ApiSecurityModule } from './api-security/api-security.module';
import { DataPipelineModule } from './data-pipeline/data-pipeline.module';
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
import { RLSCLSModule } from './rls-cls/rls-cls.module';
import { PolicyValidationModule } from './policy-validation/policy-validation.module';
import { IdentityProviderModule } from './identity-providers/identity-provider.module';
import { NetworkPolicyModule } from './network-policy/network-policy.module';
import { APIGatewayModule } from './api-gateway/api-gateway.module';
import { DLPModule } from './dlp/dlp.module';
import { TestConfigurationsModule } from './test-configurations/test-configurations.module';
import { TestResultsModule } from './test-results/test-results.module';
import { TestSuitesModule } from './test-suites/test-suites.module';
import { TestHarnessesModule } from './test-harnesses/test-harnesses.module';
import { TestBatteriesModule } from './test-batteries/test-batteries.module';
import { NotificationsModule } from './notifications/notifications.module';
import { FindingApprovalsModule } from './finding-approvals/finding-approvals.module';
import { UsersModule } from './users/users.module';
import { EnvironmentConfigModule } from './environment-config/environment-config.module';
import { APISecurityEnhancedModule } from './api-security-enhanced/api-security-enhanced.module';
import { ABACCorrectnessModule } from './abac-correctness/abac-correctness.module';
import { TestsModule } from './tests/tests.module';
import { AuthModule } from './auth/auth.module';
import { RiskScoringModule } from './risk-scoring/risk-scoring.module';
import { AppController } from './app.controller';

@Module({
  imports: [
    ThrottlerModule.forRoot([
      {
        name: 'default',
        ttl: 60000, // 1 minute
        limit: 100, // 100 requests per minute
      },
    ]),
    AuthModule,
    DashboardModule,
    ApplicationsModule,
    ValidatorsModule,
    ValidationTargetsModule,
    PoliciesModule,
    ViolationsModule,
    HistoryModule,
    ApiSecurityModule,
    DataPipelineModule,
    ReportsModule,
    DistributedSystemsModule,
    CICDModule,
    TicketingModule,
    SLAModule,
    RemediationModule,
    RemediationTrackingModule,
    ComplianceModule,
    UnifiedFindingsModule,
    IntegrationsModule,
    ScheduledReportsModule,
    SecurityModule,
    RLSCLSModule,
    PolicyValidationModule,
    IdentityProviderModule,
    NetworkPolicyModule,
    APIGatewayModule,
    DLPModule,
    TestConfigurationsModule,
    TestResultsModule,
    TestSuitesModule,
    TestHarnessesModule,
    TestBatteriesModule,
    NotificationsModule,
    FindingApprovalsModule,
    UsersModule,
    EnvironmentConfigModule,
    APISecurityEnhancedModule,
    ABACCorrectnessModule,
    TestsModule,
    RiskScoringModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(HttpsRedirectMiddleware, SanitizeMiddleware, VersionMiddleware)
      .forRoutes('*'); // Apply to all routes
  }
}
