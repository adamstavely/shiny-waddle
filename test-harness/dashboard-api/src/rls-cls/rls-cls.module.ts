import { Module } from '@nestjs/common';
import { RLSCLSController } from './rls-cls.controller';
import { RLSCLSService } from './rls-cls.service';

@Module({
  controllers: [RLSCLSController],
  providers: [RLSCLSService],
  exports: [RLSCLSService],
})
export class RLSCLSModule {}

