import { Module } from '@nestjs/common';
import { DistributedSystemsController } from './distributed-systems.controller';
import { DistributedSystemsService } from './distributed-systems.service';

@Module({
  controllers: [DistributedSystemsController],
  providers: [DistributedSystemsService],
})
export class DistributedSystemsModule {}

