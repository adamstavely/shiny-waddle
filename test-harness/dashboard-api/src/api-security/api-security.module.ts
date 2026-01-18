import { Module, forwardRef } from '@nestjs/common';
import { ApiSecurityService } from './api-security.service';
import { ApiSecurityController } from './api-security.controller';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [ApiSecurityController],
  providers: [ApiSecurityService],
  exports: [ApiSecurityService],
})
export class ApiSecurityModule {}

