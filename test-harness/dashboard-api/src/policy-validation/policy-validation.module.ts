import { Module } from '@nestjs/common';
import { PolicyValidationController } from './policy-validation.controller';
import { PolicyValidationService } from './policy-validation.service';

@Module({
  controllers: [PolicyValidationController],
  providers: [PolicyValidationService],
  exports: [PolicyValidationService],
})
export class PolicyValidationModule {}


