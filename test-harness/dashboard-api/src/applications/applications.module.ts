import { Module, forwardRef } from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { ApplicationsController } from './applications.controller';
import { TestConfigurationsModule } from '../test-configurations/test-configurations.module';
import { TestResultsModule } from '../test-results/test-results.module';

@Module({
  controllers: [ApplicationsController],
  providers: [ApplicationsService],
  exports: [ApplicationsService],
  imports: [
    forwardRef(() => TestConfigurationsModule),
    forwardRef(() => TestResultsModule),
  ],
})
export class ApplicationsModule {}

