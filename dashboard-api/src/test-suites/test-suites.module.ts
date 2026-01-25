import { Module } from '@nestjs/common';
import { TestSuitesController } from './test-suites.controller';
import { TestSuitesService } from './test-suites.service';
import { TestLoaderService } from './test-loader.service';

@Module({
  controllers: [TestSuitesController],
  providers: [TestSuitesService, TestLoaderService],
  exports: [TestSuitesService, TestLoaderService],
})
export class TestSuitesModule {}

