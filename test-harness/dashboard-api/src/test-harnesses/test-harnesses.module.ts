import { Module } from '@nestjs/common';
import { TestHarnessesController } from './test-harnesses.controller';
import { TestHarnessesService } from './test-harnesses.service';

@Module({
  controllers: [TestHarnessesController],
  providers: [TestHarnessesService],
  exports: [TestHarnessesService],
})
export class TestHarnessesModule {}

