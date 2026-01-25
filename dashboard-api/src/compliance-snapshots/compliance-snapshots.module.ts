import { Module } from '@nestjs/common';
import { ComplianceSnapshotsController } from './compliance-snapshots.controller';
import { ComplianceSnapshotsService } from './compliance-snapshots.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [
    ApplicationDataModule,
  ],
  controllers: [ComplianceSnapshotsController],
  providers: [ComplianceSnapshotsService],
  exports: [ComplianceSnapshotsService],
})
export class ComplianceSnapshotsModule {}

