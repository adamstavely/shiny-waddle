import { Module } from '@nestjs/common';
import { DistributedController } from './distributed.controller';
import { MultiRegionTestingApiService } from './multi-region-testing.service';
import { PolicyConsistencyService } from './policy-consistency.service';
import { PolicySyncService } from './policy-sync.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [DistributedController],
  providers: [
    MultiRegionTestingApiService,
    PolicyConsistencyService,
    PolicySyncService,
  ],
  exports: [
    MultiRegionTestingApiService,
    PolicyConsistencyService,
    PolicySyncService,
  ],
})
export class DistributedModule {}
