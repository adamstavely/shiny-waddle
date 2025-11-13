import { Module, forwardRef } from '@nestjs/common';
import { RLSCLSController } from './rls-cls.controller';
import { RLSCLSService } from './rls-cls.service';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [forwardRef(() => TestConfigurationsModule)],
  controllers: [RLSCLSController],
  providers: [RLSCLSService],
  exports: [RLSCLSService],
})
export class RLSCLSModule {}

