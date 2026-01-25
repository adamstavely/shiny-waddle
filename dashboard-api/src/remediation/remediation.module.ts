import { Module, forwardRef } from '@nestjs/common';
import { RemediationService } from './remediation.service';
import { TicketingModule } from '../ticketing/ticketing.module';

@Module({
  imports: [TicketingModule],
  providers: [RemediationService],
  exports: [RemediationService],
})
export class RemediationModule {}

