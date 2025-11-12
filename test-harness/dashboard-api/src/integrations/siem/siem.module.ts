import { Module } from '@nestjs/common';
import { SIEMController } from './siem.controller';
import { SIEMService } from './siem.service';

@Module({
  controllers: [SIEMController],
  providers: [SIEMService],
  exports: [SIEMService],
})
export class SIEMModule {}

