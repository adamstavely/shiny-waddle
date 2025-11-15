import { Module } from '@nestjs/common';
import { APISecurityEnhancedController } from './api-security-enhanced.controller';
import { APISecurityEnhancedService } from './api-security-enhanced.service';

@Module({
  controllers: [APISecurityEnhancedController],
  providers: [APISecurityEnhancedService],
  exports: [APISecurityEnhancedService],
})
export class APISecurityEnhancedModule {}

