import { Module } from '@nestjs/common';
import { RunsController } from './runs.controller';
import { RunsService } from './runs.service';
import { TestResultsModule } from '../test-results/test-results.module';
import { TestBatteriesModule } from '../test-batteries/test-batteries.module';
import { TestHarnessesModule } from '../test-harnesses/test-harnesses.module';
import { TestSuitesModule } from '../test-suites/test-suites.module';

@Module({
  imports: [
    TestResultsModule,
    TestBatteriesModule,
    TestHarnessesModule,
    TestSuitesModule,
  ],
  controllers: [RunsController],
  providers: [RunsService],
  exports: [RunsService],
})
export class RunsModule {}

