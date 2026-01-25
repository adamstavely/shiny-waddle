import { Module, forwardRef } from '@nestjs/common';
import { DataPipelineService } from './data-pipeline.service';
import { DataPipelineController } from './data-pipeline.controller';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [DataPipelineController],
  providers: [DataPipelineService],
  exports: [DataPipelineService],
})
export class DataPipelineModule {}

