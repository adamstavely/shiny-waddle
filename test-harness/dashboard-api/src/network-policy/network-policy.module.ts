import { Module } from '@nestjs/common';
import { NetworkPolicyController } from './network-policy.controller';
import { NetworkPolicyService } from './network-policy.service';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [TestConfigurationsModule],
  controllers: [NetworkPolicyController],
  providers: [NetworkPolicyService],
  exports: [NetworkPolicyService],
})
export class NetworkPolicyModule {}

