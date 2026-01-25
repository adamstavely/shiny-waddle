import { Module } from '@nestjs/common';
import { RLSCLSController } from './rls-cls.controller';
import { RLSCLSService } from './rls-cls.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [RLSCLSController],
  providers: [RLSCLSService],
  exports: [RLSCLSService],
})
export class RLSCLSModule {}

