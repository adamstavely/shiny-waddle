import { Module, forwardRef } from '@nestjs/common';
import { NetworkPolicyController } from './network-policy.controller';
import { NetworkPolicyService } from './network-policy.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [NetworkPolicyController],
  providers: [NetworkPolicyService],
  exports: [NetworkPolicyService],
})
export class NetworkPolicyModule {}

