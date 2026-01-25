import { Module } from '@nestjs/common';
import { SalesforceExperienceCloudService } from './salesforce-experience-cloud.service';
import { SalesforceExperienceCloudController } from './salesforce-experience-cloud.controller';

@Module({
  controllers: [SalesforceExperienceCloudController],
  providers: [SalesforceExperienceCloudService],
  exports: [SalesforceExperienceCloudService],
})
export class SalesforceExperienceCloudModule {}
