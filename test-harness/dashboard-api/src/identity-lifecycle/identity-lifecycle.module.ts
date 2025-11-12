import { Module } from '@nestjs/common';
import { IdentityLifecycleController } from './identity-lifecycle.controller';
import { IdentityLifecycleService } from './identity-lifecycle.service';

@Module({
  controllers: [IdentityLifecycleController],
  providers: [IdentityLifecycleService],
  exports: [IdentityLifecycleService],
})
export class IdentityLifecycleModule {}

