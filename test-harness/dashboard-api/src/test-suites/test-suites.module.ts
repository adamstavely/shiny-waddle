import { Module } from '@nestjs/common';
import { TestSuitesController } from './test-suites.controller';
import { TestSuitesService } from './test-suites.service';

@Module({
  controllers: [TestSuitesController],
  providers: [TestSuitesService],
  exports: [TestSuitesService],
})
export class TestSuitesModule {}

