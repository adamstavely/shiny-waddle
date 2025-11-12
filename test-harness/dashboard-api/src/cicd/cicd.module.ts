import { Module } from '@nestjs/common';
import { CICDController } from './cicd.controller';
import { CICDService } from './cicd.service';
import { SecurityGatesController } from './security-gates.controller';
import { SecurityGatesService } from './security-gates.service';

@Module({
  controllers: [CICDController, SecurityGatesController],
  providers: [CICDService, SecurityGatesService],
  exports: [CICDService, SecurityGatesService],
})
export class CICDModule {}

