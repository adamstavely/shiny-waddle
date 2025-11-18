import { Module } from '@nestjs/common';
import { DataClassificationController } from './data-classification.controller';
import { DataClassificationService } from './data-classification.service';

@Module({
  controllers: [DataClassificationController],
  providers: [DataClassificationService],
  exports: [DataClassificationService],
})
export class DataClassificationModule {}

