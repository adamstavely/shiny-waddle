import { Module, forwardRef } from '@nestjs/common';
import { DataPipelineService } from './data-pipeline.service';
import { DataPipelineController } from './data-pipeline.controller';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [forwardRef(() => TestConfigurationsModule)],
  controllers: [DataPipelineController],
  providers: [DataPipelineService],
  exports: [DataPipelineService],
})
export class DataPipelineModule {}

