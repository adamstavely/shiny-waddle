import { Module } from '@nestjs/common';
import { UnifiedFindingsController } from './unified-findings.controller';
import { UnifiedFindingsService } from './unified-findings.service';
import { ApplicationDataModule } from '../shared/application-data.module';
import { UsersModule } from '../users/users.module';

@Module({
  imports: [
    ApplicationDataModule,
    UsersModule,
  ],
  controllers: [UnifiedFindingsController],
  providers: [UnifiedFindingsService],
  exports: [UnifiedFindingsService],
})
export class UnifiedFindingsModule {}

