import { Module } from '@nestjs/common';
import { CloudProviderController } from './cloud-provider.controller';
import { CloudProviderService } from './cloud-provider.service';

@Module({
  controllers: [CloudProviderController],
  providers: [CloudProviderService],
  exports: [CloudProviderService],
})
export class CloudProviderModule {}

