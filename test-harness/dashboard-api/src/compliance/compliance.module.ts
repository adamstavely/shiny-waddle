import { Module } from '@nestjs/common';
import { ComplianceController } from './compliance.controller';
import { ComplianceService } from './compliance.service';
import { NIST800207Controller } from './nist-800-207.controller';
import { NIST800207Service } from './nist-800-207.service';
import { ViolationsModule } from '../violations/violations.module';

@Module({
  imports: [ViolationsModule],
  controllers: [ComplianceController, NIST800207Controller],
  providers: [ComplianceService, NIST800207Service],
  exports: [ComplianceService, NIST800207Service],
})
export class ComplianceModule {}

