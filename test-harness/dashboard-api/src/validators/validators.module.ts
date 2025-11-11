import { Module } from '@nestjs/common';
import { ValidatorsController } from './validators.controller';
import { ValidatorsService } from './validators.service';

@Module({
  controllers: [ValidatorsController],
  providers: [ValidatorsService],
  exports: [ValidatorsService],
})
export class ValidatorsModule {}

