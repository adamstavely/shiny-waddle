import { Module } from '@nestjs/common';
import { EnvironmentConfigController } from './environment-config.controller';
import { EnvironmentConfigService } from './environment-config.service';

@Module({
  controllers: [EnvironmentConfigController],
  providers: [EnvironmentConfigService],
  exports: [EnvironmentConfigService],
})
export class EnvironmentConfigModule {}

