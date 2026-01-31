import { Module, forwardRef } from '@nestjs/common';
import { PoliciesModule } from '../policies.module';
import { PolicyBuilderController } from './policy-builder.controller';
import { PolicyBuilderService } from './services/policy-builder.service';
import { PolicyValidationService } from './services/policy-validation.service';
import { PolicyDiffService } from './services/policy-diff.service';
import { PolicyTemplateService } from './services/policy-template.service';

@Module({
  imports: [forwardRef(() => PoliciesModule)],
  controllers: [PolicyBuilderController],
  providers: [
    PolicyBuilderService,
    PolicyValidationService,
    PolicyDiffService,
    PolicyTemplateService,
  ],
  exports: [
    PolicyBuilderService,
    PolicyValidationService,
    PolicyDiffService,
    PolicyTemplateService,
  ],
})
export class PolicyBuilderModule {}
