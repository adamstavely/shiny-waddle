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
import { AppController } from './app.controller';

@Module({
  imports: [DashboardModule, ApplicationsModule, ValidatorsModule, ValidationTargetsModule, PoliciesModule, ViolationsModule, HistoryModule, ApiSecurityModule, ReportsModule, DistributedSystemsModule, CICDModule],
  controllers: [AppController],
})
export class AppModule {}
