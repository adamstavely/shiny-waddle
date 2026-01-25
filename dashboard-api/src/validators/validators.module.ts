import { Module } from '@nestjs/common';
import { ValidatorsController } from './validators.controller';
import { ValidatorsService } from './validators.service';
import { ValidatorDiscoveryService } from './validator-discovery.service';

@Module({
  controllers: [ValidatorsController],
  providers: [ValidatorsService, ValidatorDiscoveryService],
  exports: [ValidatorsService],
})
export class ValidatorsModule {}

