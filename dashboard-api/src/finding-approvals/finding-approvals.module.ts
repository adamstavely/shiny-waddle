import { Module } from '@nestjs/common';
import { FindingApprovalsController } from './finding-approvals.controller';
import { FindingApprovalsService } from './finding-approvals.service';

@Module({
  controllers: [FindingApprovalsController],
  providers: [FindingApprovalsService],
})
export class FindingApprovalsModule {}

