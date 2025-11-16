import { Module, forwardRef } from '@nestjs/common';
import { TestBatteriesController } from './test-batteries.controller';
import { TestBatteriesService } from './test-batteries.service';
import { TestHarnessesModule } from '../test-harnesses/test-harnesses.module';

@Module({
  imports: [forwardRef(() => TestHarnessesModule)],
  controllers: [TestBatteriesController],
  providers: [TestBatteriesService],
  exports: [TestBatteriesService],
})
export class TestBatteriesModule {}

