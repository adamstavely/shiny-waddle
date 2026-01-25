import { Module } from '@nestjs/common';
import { SalesforceBaselinesController } from './salesforce-baselines.controller';
import { SalesforceBaselinesService } from './salesforce-baselines.service';

@Module({
  controllers: [SalesforceBaselinesController],
  providers: [SalesforceBaselinesService],
  exports: [SalesforceBaselinesService],
})
export class SalesforceBaselinesModule {}
