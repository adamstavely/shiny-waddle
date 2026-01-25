import { Module, forwardRef } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { ComplianceService } from './compliance.service';
import { NIST800207Controller } from './nist-800-207.controller';
import { NIST800207Service } from './nist-800-207.service';
import { ComplianceScoresController } from './compliance-scores.controller';
import { ComplianceScoresService } from './compliance-scores.service';
import { ViolationsModule } from '../violations/violations.module';
import { UnifiedFindingsModule } from '../unified-findings/unified-findings.module';
import { TestResultsModule } from '../test-results/test-results.module';

@Module({
  imports: [
    ViolationsModule,
    forwardRef(() => UnifiedFindingsModule),
    forwardRef(() => TestResultsModule),
  ],
  controllers: [ComplianceController, NIST800207Controller, ComplianceScoresController],
  providers: [ComplianceService, NIST800207Service, ComplianceScoresService],
  exports: [ComplianceService, NIST800207Service, ComplianceScoresService],
})
export class ComplianceModule {}

