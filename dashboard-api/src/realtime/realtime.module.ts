import { Module } from '@nestjs/common';
import { RealtimeService } from './realtime.service';
import { RealtimeController } from './realtime.controller';
import { DashboardModule } from '../dashboard/dashboard.module';
import { UnifiedFindingsModule } from '../unified-findings/unified-findings.module';
import { ElasticsearchModule } from '../elasticsearch/elasticsearch.module';

@Module({
  imports: [
    DashboardModule, // For DashboardSSEGateway
    UnifiedFindingsModule, // For storing findings
    ElasticsearchModule, // For Elasticsearch integration
  ],
  controllers: [RealtimeController],
  providers: [RealtimeService],
  exports: [RealtimeService],
})
export class RealtimeModule {}
