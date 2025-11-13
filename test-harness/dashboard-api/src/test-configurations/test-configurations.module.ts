import { Module, forwardRef } from '@nestjs/common';
import { TestConfigurationsController } from './test-configurations.controller';
import { TestConfigurationsService } from './test-configurations.service';
import { RLSCLSModule } from '../rls-cls/rls-cls.module';
import { DLPModule } from '../dlp/dlp.module';
import { IdentityLifecycleModule } from '../identity-lifecycle/identity-lifecycle.module';
import { APIGatewayModule } from '../api-gateway/api-gateway.module';
import { NetworkPolicyModule } from '../network-policy/network-policy.module';
import { DistributedSystemsModule } from '../distributed-systems/distributed-systems.module';
import { ApplicationsModule } from '../applications/applications.module';
import { TestResultsModule } from '../test-results/test-results.module';

@Module({
  imports: [
    forwardRef(() => RLSCLSModule),
    forwardRef(() => DLPModule),
    forwardRef(() => IdentityLifecycleModule),
    forwardRef(() => APIGatewayModule),
    forwardRef(() => NetworkPolicyModule),
    forwardRef(() => DistributedSystemsModule),
    forwardRef(() => ApplicationsModule),
    forwardRef(() => TestResultsModule),
  ],
  controllers: [TestConfigurationsController],
  providers: [TestConfigurationsService],
  exports: [TestConfigurationsService],
})
export class TestConfigurationsModule {}

