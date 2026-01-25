import { Module } from '@nestjs/common';
import { PoliciesController } from './policies.controller';
import { PoliciesService } from './policies.service';
import { PolicyVersioningService } from './services/policy-versioning.service';

@Module({
  controllers: [PoliciesController],
  providers: [PoliciesService, PolicyVersioningService],
  exports: [PoliciesService, PolicyVersioningService],
})
export class PoliciesModule {}

