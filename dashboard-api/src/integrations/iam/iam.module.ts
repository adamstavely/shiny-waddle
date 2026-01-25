import { Module } from '@nestjs/common';
import { IAMController } from './iam.controller';
import { IAMService } from './iam.service';

@Module({
  controllers: [IAMController],
  providers: [IAMService],
  exports: [IAMService],
})
export class IAMModule {}

