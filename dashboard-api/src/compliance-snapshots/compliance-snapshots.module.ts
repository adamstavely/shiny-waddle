import { Module, forwardRef } from '@nestjs/common';
import { ComplianceSnapshotsController } from './compliance-snapshots.controller';
import { ComplianceSnapshotsService } from './compliance-snapshots.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [
    forwardRef(() => ApplicationsModule),
  ],
  controllers: [ComplianceSnapshotsController],
  providers: [ComplianceSnapshotsService],
  exports: [ComplianceSnapshotsService],
})
export class ComplianceSnapshotsModule {}

