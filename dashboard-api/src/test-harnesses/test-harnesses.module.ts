import { Module, forwardRef } from '@nestjs/common';
import { TestHarnessesController } from './test-harnesses.controller';
import { TestHarnessesService } from './test-harnesses.service';
import { TestSuitesModule } from '../test-suites/test-suites.module';

@Module({
  imports: [forwardRef(() => TestSuitesModule)],
  controllers: [TestHarnessesController],
  providers: [TestHarnessesService],
  exports: [TestHarnessesService],
})
export class TestHarnessesModule {}

