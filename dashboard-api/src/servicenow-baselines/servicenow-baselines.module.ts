import { Module } from '@nestjs/common';
import { ServiceNowBaselinesController } from './servicenow-baselines.controller';
import { ServiceNowBaselinesService } from './servicenow-baselines.service';

@Module({
  controllers: [ServiceNowBaselinesController],
  providers: [ServiceNowBaselinesService],
  exports: [ServiceNowBaselinesService],
})
export class ServiceNowBaselinesModule {}
