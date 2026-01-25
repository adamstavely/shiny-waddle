import { Module } from '@nestjs/common';
import { DistributedSystemsController } from './distributed-systems.controller';
import { DistributedSystemsService } from './distributed-systems.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [DistributedSystemsController],
  providers: [DistributedSystemsService],
  exports: [DistributedSystemsService],
})
export class DistributedSystemsModule {}

