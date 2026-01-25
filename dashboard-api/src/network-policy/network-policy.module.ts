import { Module } from '@nestjs/common';
import { NetworkPolicyController } from './network-policy.controller';
import { NetworkPolicyService } from './network-policy.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [NetworkPolicyController],
  providers: [NetworkPolicyService],
  exports: [NetworkPolicyService],
})
export class NetworkPolicyModule {}

