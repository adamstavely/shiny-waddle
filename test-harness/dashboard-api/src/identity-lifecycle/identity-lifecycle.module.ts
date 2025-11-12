import { Module } from '@nestjs/common';
import { IdentityLifecycleController } from './identity-lifecycle.controller';
import { IdentityLifecycleService } from './identity-lifecycle.service';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [TestConfigurationsModule],
  controllers: [IdentityLifecycleController],
  providers: [IdentityLifecycleService],
  exports: [IdentityLifecycleService],
})
export class IdentityLifecycleModule {}

