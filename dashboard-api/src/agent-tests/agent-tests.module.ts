import { Module } from '@nestjs/common';
import { AgentTestsController } from './agent-tests.controller';
import { AgentTestsService } from './agent-tests.service';
import { SecurityModule } from '../security/security.module';

@Module({
  imports: [SecurityModule],
  controllers: [AgentTestsController],
  providers: [AgentTestsService],
  exports: [AgentTestsService],
})
export class AgentTestsModule {}
