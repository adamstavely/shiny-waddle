import { Module } from '@nestjs/common';
import { NetworkPolicyController } from './network-policy.controller';
import { NetworkPolicyService } from './network-policy.service';

@Module({
  controllers: [NetworkPolicyController],
  providers: [NetworkPolicyService],
  exports: [NetworkPolicyService],
})
export class NetworkPolicyModule {}

