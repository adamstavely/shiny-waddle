import { Module, forwardRef } from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { ApplicationsController } from './applications.controller';
import { TestResultsModule } from '../test-results/test-results.module';
import { SecurityModule } from '../security/security.module';
import { ValidatorsModule } from '../validators/validators.module';
import { TestHarnessesModule } from '../test-harnesses/test-harnesses.module';
import { TestBatteriesModule } from '../test-batteries/test-batteries.module';
import { CICDModule } from '../cicd/cicd.module';

@Module({
  controllers: [ApplicationsController],
  providers: [ApplicationsService],
  exports: [ApplicationsService],
  imports: [
    forwardRef(() => TestResultsModule),
    forwardRef(() => SecurityModule),
    forwardRef(() => ValidatorsModule),
    forwardRef(() => TestHarnessesModule),
    forwardRef(() => TestBatteriesModule),
    CICDModule,
  ],
})
export class ApplicationsModule {}

