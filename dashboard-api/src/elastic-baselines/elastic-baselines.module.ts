import { Module } from '@nestjs/common';
import { ElasticBaselinesController } from './elastic-baselines.controller';
import { ElasticBaselinesService } from './elastic-baselines.service';

@Module({
  controllers: [ElasticBaselinesController],
  providers: [ElasticBaselinesService],
  exports: [ElasticBaselinesService],
})
export class ElasticBaselinesModule {}
