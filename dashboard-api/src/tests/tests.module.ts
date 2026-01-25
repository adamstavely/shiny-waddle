import { Module } from '@nestjs/common';
import { TestsController } from './tests.controller';
import { TestsAliasController } from './tests-alias.controller';
import { TestsService } from './tests.service';
import { TestDiscoveryService } from './test-discovery.service';

@Module({
  controllers: [TestsController, TestsAliasController],
  providers: [TestsService, TestDiscoveryService],
  exports: [TestsService],
})
export class TestsModule {}

