import { Module } from '@nestjs/common';
import { ValidationTargetsController, ValidationRulesController } from './validation-targets.controller';
import { ValidationTargetsService } from './validation-targets.service';

@Module({
  controllers: [ValidationTargetsController, ValidationRulesController],
  providers: [ValidationTargetsService],
  exports: [ValidationTargetsService],
})
export class ValidationTargetsModule {}

