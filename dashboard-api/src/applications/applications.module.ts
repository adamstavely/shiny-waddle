import { Module, forwardRef } from '@nestjs/common';
import { ApplicationsService } from './applications.service';
import { ApplicationsController } from './applications.controller';
import { TestResultsModule } from '../test-results/test-results.module';
import { ValidatorsModule } from '../validators/validators.module';
import { CICDModule } from '../cicd/cicd.module';
import { SecurityModule } from '../security/security.module';

@Module({
  controllers: [ApplicationsController],
  providers: [ApplicationsService],
  exports: [ApplicationsService],
  imports: [
    forwardRef(() => TestResultsModule),
    forwardRef(() => ValidatorsModule),
    CICDModule,
    SecurityModule,
  ],
})
export class ApplicationsModule {}

