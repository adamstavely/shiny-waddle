import { Module } from '@nestjs/common';
import { DataPipelineService } from './data-pipeline.service';
import { DataPipelineController } from './data-pipeline.controller';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [DataPipelineController],
  providers: [DataPipelineService],
  exports: [DataPipelineService],
})
export class DataPipelineModule {}

