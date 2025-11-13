import { Module, forwardRef } from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { ApplicationsController } from './applications.controller';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';
import { TestResultsModule } from '../test-results/test-results.module';
import { SecurityModule } from '../security/security.module';
import { ValidatorsModule } from '../validators/validators.module';

@Module({
  controllers: [ApplicationsController],
  providers: [ApplicationsService],
  exports: [ApplicationsService],
  imports: [
    forwardRef(() => TestConfigurationsModule),
    forwardRef(() => TestResultsModule),
    forwardRef(() => SecurityModule),
    forwardRef(() => ValidatorsModule),
  ],
})
export class ApplicationsModule {}

