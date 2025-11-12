import { Module } from '@nestjs/common';
import { DLPController } from './dlp.controller';
import { DLPService } from './dlp.service';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';

@Module({
  imports: [TestConfigurationsModule],
  controllers: [DLPController],
  providers: [DLPService],
  exports: [DLPService],
})
export class DLPModule {}

