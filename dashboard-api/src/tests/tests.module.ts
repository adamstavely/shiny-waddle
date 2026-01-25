import { Module } from '@nestjs/common';
import { TestsController } from './tests.controller';
import { TestsAliasController } from './tests-alias.controller';
import { TestsService } from './tests.service';
import { TestDiscoveryService } from './test-discovery.service';
import { ApplicationDataModule } from '../shared/application-data.module';

@Module({
  imports: [ApplicationDataModule],
  controllers: [TestsController, TestsAliasController],
  providers: [TestsService, TestDiscoveryService],
  exports: [TestsService],
})
export class TestsModule {}

