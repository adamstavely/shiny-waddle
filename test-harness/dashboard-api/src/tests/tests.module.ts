import { Module, forwardRef } from '@nestjs/common';
import { TestsController } from './tests.controller';
import { TestsAliasController } from './tests-alias.controller';
import { TestsService } from './tests.service';
import { PoliciesModule } from '../policies/policies.module';

@Module({
  imports: [forwardRef(() => PoliciesModule)],
  controllers: [TestsController, TestsAliasController],
  providers: [TestsService],
  exports: [TestsService],
})
export class TestsModule {}

