import { Module } from '@nestjs/common';
import { ABACCorrectnessController } from './abac-correctness.controller';
import { ABACCorrectnessService } from './abac-correctness.service';

@Module({
  controllers: [ABACCorrectnessController],
  providers: [ABACCorrectnessService],
  exports: [ABACCorrectnessService],
})
export class ABACCorrectnessModule {}

