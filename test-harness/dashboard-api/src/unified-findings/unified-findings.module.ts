import { Module } from '@nestjs/common';
import { UnifiedFindingsController } from './unified-findings.controller';
import { UnifiedFindingsService } from './unified-findings.service';

@Module({
  controllers: [UnifiedFindingsController],
  providers: [UnifiedFindingsService],
})
export class UnifiedFindingsModule {}

