import { Module } from '@nestjs/common';
import { DLPController } from './dlp.controller';
import { DLPService } from './dlp.service';

@Module({
  controllers: [DLPController],
  providers: [DLPService],
  exports: [DLPService],
})
export class DLPModule {}

