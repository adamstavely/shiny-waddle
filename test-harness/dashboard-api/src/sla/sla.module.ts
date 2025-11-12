import { Module } from '@nestjs/common';
import { SLAController } from './sla.controller';
import { SLAService } from './sla.service';

@Module({
  controllers: [SLAController],
  providers: [SLAService],
  exports: [SLAService],
})
export class SLAModule {}

