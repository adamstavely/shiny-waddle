import { Module } from '@nestjs/common';
import { SalesforceExperienceCloudController } from './salesforce-experience-cloud.controller';
import { SalesforceExperienceCloudService } from './salesforce-experience-cloud.service';

@Module({
  controllers: [SalesforceExperienceCloudController],
  providers: [SalesforceExperienceCloudService],
  exports: [SalesforceExperienceCloudService],
})
export class SalesforceExperienceCloudModule {}
