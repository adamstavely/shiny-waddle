import { Module, MiddlewareConsumer, NestModule } from '@nestjs/common';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { VersionMiddleware } from './common/middleware/version.middleware';
import { HttpsRedirectMiddleware } from './common/middleware/https-redirect.middleware';
import { SanitizeMiddleware } from './common/middleware/sanitize.middleware';
import { DotRouteMiddleware } from './common/middleware/dot-route.middleware';
import { DashboardModule } from './dashboard/dashboard.module';
import { ApplicationsModule } from './applications/applications.module';
import { ValidatorsModule } from './validators/validators.module';
import { ValidationTargetsModule } from './validation-targets/validation-targets.module';
import { PoliciesModule } from './policies/policies.module';
import { ViolationsModule } from './violations/violations.module';
import { HistoryModule } from './history/history.module';
import { ApiSecurityModule } from './api-security/api-security.module';
import { DataPipelineModule } from './data-pipeline/data-pipeline.module';
import { DistributedSystemsModule } from './distributed-systems/distributed-systems.module';
import { CICDModule } from './cicd/cicd.module';
import { TicketingModule } from './ticketing/ticketing.module';
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
import { TestResultsModule } from './test-results/test-results.module';
import { TestSuitesModule } from './test-suites/test-suites.module';
import { TestHarnessesModule } from './test-harnesses/test-harnesses.module';
import { TestBatteriesModule } from './test-batteries/test-batteries.module';
import { RunsModule } from './runs/runs.module';
import { ComplianceSnapshotsModule } from './compliance-snapshots/compliance-snapshots.module';
import { NotificationsModule } from './notifications/notifications.module';
import { FindingApprovalsModule } from './finding-approvals/finding-approvals.module';
import { UsersModule } from './users/users.module';
import { EnvironmentConfigModule } from './environment-config/environment-config.module';
import { TestsModule } from './tests/tests.module';
import { AuthModule } from './auth/auth.module';
import { RiskScoringModule } from './risk-scoring/risk-scoring.module';
import { DataClassificationModule } from './data-classification/data-classification.module';
import { ExceptionsModule } from './exceptions/exceptions.module';
import { StandardsMappingModule } from './standards-mapping/standards-mapping.module';
import { SalesforceExperienceCloudModule } from './salesforce-experience-cloud/salesforce-experience-cloud.module';
import { AlertingModule } from './alerting/alerting.module';
import { SalesforceBaselinesModule } from './salesforce-baselines/salesforce-baselines.module';
import { ElasticBaselinesModule } from './elastic-baselines/elastic-baselines.module';
import { IDPKubernetesBaselinesModule } from './idp-kubernetes-baselines/idp-kubernetes-baselines.module';
import { ServiceNowBaselinesModule } from './servicenow-baselines/servicenow-baselines.module';
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
    DistributedSystemsModule,
    CICDModule,
    TicketingModule,
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
    TestResultsModule,
    TestSuitesModule,
    TestHarnessesModule,
    TestBatteriesModule,
    RunsModule,
    ComplianceSnapshotsModule,
    NotificationsModule,
    FindingApprovalsModule,
    UsersModule,
    EnvironmentConfigModule,
    TestsModule,
    RiskScoringModule,
    DataClassificationModule,
    ExceptionsModule,
    StandardsMappingModule,
    SalesforceExperienceCloudModule,
    AlertingModule,
    SalesforceBaselinesModule,
    ElasticBaselinesModule,
    IDPKubernetesBaselinesModule,
    ServiceNowBaselinesModule,
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
      .apply(HttpsRedirectMiddleware, SanitizeMiddleware, VersionMiddleware, DotRouteMiddleware)
      .forRoutes('*'); // Apply to all routes
  }
}
