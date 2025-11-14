import { Module } from '@nestjs/common';
import { TestBatteriesController } from './test-batteries.controller';
import { TestBatteriesService } from './test-batteries.service';

@Module({
  controllers: [TestBatteriesController],
  providers: [TestBatteriesService],
  exports: [TestBatteriesService],
})
export class TestBatteriesModule {}

