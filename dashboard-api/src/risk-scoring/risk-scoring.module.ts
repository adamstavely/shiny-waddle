import { Module } from '@nestjs/common';
import { RiskScoringController } from './risk-scoring.controller';
import { EnhancedRiskScoringService } from './services/enhanced-risk-scoring.service';
import { TestResultsModule } from '../test-results/test-results.module';

@Module({
  imports: [TestResultsModule],
  controllers: [RiskScoringController],
  providers: [EnhancedRiskScoringService],
  exports: [EnhancedRiskScoringService],
})
export class RiskScoringModule {}

