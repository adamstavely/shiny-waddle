import { Module, forwardRef } from '@nestjs/common';
import { RLSCLSController } from './rls-cls.controller';
import { RLSCLSService } from './rls-cls.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [RLSCLSController],
  providers: [RLSCLSService],
  exports: [RLSCLSService],
})
export class RLSCLSModule {}

