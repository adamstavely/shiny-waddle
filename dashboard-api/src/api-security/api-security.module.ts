import { Module } from '@nestjs/common';
import { ApiSecurityService } from './api-security.service';
import { ApiSecurityController } from './api-security.controller';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [ApiSecurityController],
  providers: [ApiSecurityService],
  exports: [ApiSecurityService],
})
export class ApiSecurityModule {}

