import { Module } from '@nestjs/common';
import { BatchOperationsController } from './batch-operations.controller';
import { BatchOperationsService } from './batch-operations.service';

@Module({
  controllers: [BatchOperationsController],
  providers: [BatchOperationsService],
  exports: [BatchOperationsService],
})
export class BatchOperationsModule {}
