import { Module } from '@nestjs/common';
import { UnifiedFindingsController } from './unified-findings.controller';
import { UnifiedFindingsService } from './unified-findings.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [ApplicationsModule],
  controllers: [UnifiedFindingsController],
  providers: [UnifiedFindingsService],
})
export class UnifiedFindingsModule {}

