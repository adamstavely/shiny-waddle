import { Module } from '@nestjs/common';
import { IDPKubernetesBaselinesController } from './idp-kubernetes-baselines.controller';
import { IDPKubernetesBaselinesService } from './idp-kubernetes-baselines.service';

@Module({
  controllers: [IDPKubernetesBaselinesController],
  providers: [IDPKubernetesBaselinesService],
  exports: [IDPKubernetesBaselinesService],
})
export class IDPKubernetesBaselinesModule {}
