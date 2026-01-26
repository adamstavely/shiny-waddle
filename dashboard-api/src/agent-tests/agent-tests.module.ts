import { Module } from '@nestjs/common';
import { AgentTestsController } from './agent-tests.controller';
import { AgentTestsService } from './agent-tests.service';

@Module({
  controllers: [AgentTestsController],
  providers: [AgentTestsService],
  exports: [AgentTestsService],
})
export class AgentTestsModule {}
