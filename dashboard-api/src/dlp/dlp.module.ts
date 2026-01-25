import { Module } from '@nestjs/common';
import { DLPController } from './dlp.controller';
import { DLPService } from './dlp.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [DLPController],
  providers: [DLPService],
  exports: [DLPService],
})
export class DLPModule {}

