import { Module } from '@nestjs/common';
import { CICDController } from './cicd.controller';
import { CICDService } from './cicd.service';

@Module({
  controllers: [CICDController],
  providers: [CICDService],
})
export class CICDModule {}

