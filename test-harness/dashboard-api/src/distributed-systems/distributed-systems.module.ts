import { Module, forwardRef } from '@nestjs/common';
import { DistributedSystemsController } from './distributed-systems.controller';
import { DistributedSystemsService } from './distributed-systems.service';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [forwardRef(() => TestConfigurationsModule)],
  controllers: [DistributedSystemsController],
  providers: [DistributedSystemsService],
  exports: [DistributedSystemsService],
})
export class DistributedSystemsModule {}

