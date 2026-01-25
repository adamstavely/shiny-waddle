import { Module, forwardRef } from '@nestjs/common';
import { PoliciesController } from './policies.controller';
import { PoliciesService } from './policies.service';
import { PolicyVersioningService } from './services/policy-versioning.service';
import { TestResultsModule } from '../test-results/test-results.module';

@Module({
  controllers: [PoliciesController],
  providers: [PoliciesService, PolicyVersioningService],
  exports: [PoliciesService, PolicyVersioningService],
  imports: [forwardRef(() => TestResultsModule)],
})
export class PoliciesModule {}

