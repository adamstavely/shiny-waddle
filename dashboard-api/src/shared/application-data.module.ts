import { Module } from '@nestjs/common';
import { ApplicationDataService } from './application-data.service';

/**
 * ApplicationDataModule - Provides read-only access to application data
 * 
 * This module exports ApplicationDataService which provides read-only methods
 * for accessing application data without circular dependencies. Services that
 * only need to read application data should import this module instead of
 * ApplicationsModule.
 */
@Module({
  providers: [ApplicationDataService],
  exports: [ApplicationDataService],
})
export class ApplicationDataModule {}
