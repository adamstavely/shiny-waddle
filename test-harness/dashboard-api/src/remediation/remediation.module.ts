import { Module, forwardRef } from '@nestjs/common';
import { RemediationService } from './remediation.service';
import { TicketingModule } from '../ticketing/ticketing.module';
import { SLAModule } from '../sla/sla.module';

@Module({
  imports: [TicketingModule, SLAModule],
  providers: [RemediationService],
  exports: [RemediationService],
})
export class RemediationModule {}

