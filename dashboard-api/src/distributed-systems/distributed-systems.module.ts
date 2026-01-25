import { Module, forwardRef } from '@nestjs/common';
import { DistributedSystemsController } from './distributed-systems.controller';
import { DistributedSystemsService } from './distributed-systems.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [DistributedSystemsController],
  providers: [DistributedSystemsService],
  exports: [DistributedSystemsService],
})
export class DistributedSystemsModule {}

