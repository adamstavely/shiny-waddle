import { Module, forwardRef } from '@nestjs/common';
import { ApiSecurityService } from './api-security.service';
import { ApiSecurityController } from './api-security.controller';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [forwardRef(() => TestConfigurationsModule)],
  controllers: [ApiSecurityController],
  providers: [ApiSecurityService],
  exports: [ApiSecurityService],
})
export class ApiSecurityModule {}

