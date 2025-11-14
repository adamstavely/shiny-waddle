import { Module, forwardRef } from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { ApplicationsController } from './applications.controller';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';
import { TestResultsModule } from '../test-results/test-results.module';
import { SecurityModule } from '../security/security.module';
import { ValidatorsModule } from '../validators/validators.module';
import { TestHarnessesModule } from '../test-harnesses/test-harnesses.module';
import { TestBatteriesModule } from '../test-batteries/test-batteries.module';

@Module({
  controllers: [ApplicationsController],
  providers: [ApplicationsService],
  exports: [ApplicationsService],
  imports: [
    forwardRef(() => TestConfigurationsModule),
    forwardRef(() => TestResultsModule),
    forwardRef(() => SecurityModule),
    forwardRef(() => ValidatorsModule),
    forwardRef(() => TestHarnessesModule),
    forwardRef(() => TestBatteriesModule),
  ],
})
export class ApplicationsModule {}

