import { Module, forwardRef } from '@nestjs/common';
import { DLPController } from './dlp.controller';
import { DLPService } from './dlp.service';
import { ApplicationsModule } from '../applications/applications.module';

@Module({
  imports: [forwardRef(() => ApplicationsModule)],
  controllers: [DLPController],
  providers: [DLPService],
  exports: [DLPService],
})
export class DLPModule {}

