import { Module } from '@nestjs/common';
import { IntegrationsController } from './integrations.controller';
import { IntegrationsService } from './integrations.service';
import { CICDModule } from '../cicd/cicd.module';
import { SIEMModule } from './siem/siem.module';
import { CloudProviderModule } from './cloud-provider/cloud-provider.module';
import { IAMModule } from './iam/iam.module';

@Module({
  imports: [CICDModule, SIEMModule, CloudProviderModule, IAMModule],
  controllers: [IntegrationsController],
  providers: [IntegrationsService],
  exports: [IntegrationsService],
})
export class IntegrationsModule {}

