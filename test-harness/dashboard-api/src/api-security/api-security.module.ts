import { Module } from '@nestjs/common';
import { ApiSecurityService } from './api-security.service';
import { ApiSecurityController } from './api-security.controller';

@Module({
  controllers: [ApiSecurityController],
  providers: [ApiSecurityService],
  exports: [ApiSecurityService],
})
export class ApiSecurityModule {}

