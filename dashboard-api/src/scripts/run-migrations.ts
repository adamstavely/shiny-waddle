/**
 * Migration Runner
 * 
 * Bootstraps NestJS application and runs migration scripts
 */

import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { ApplicationsService } from '../applications/applications.service';
import { TestSuitesService } from '../test-suites/test-suites.service';
import { migrateTestsToPolicy1to1 } from './migrate-tests-to-policy-1to1';

async function bootstrap() {
  const app = await NestFactory.createApplicationContext(AppModule);
  
  const appsService = app.get(ApplicationsService);
  const suitesService = app.get(TestSuitesService);
  
  // Try to get TestsService and PoliciesService
  let testsService: any = null;
  let policiesService: any = null;
  try {
    testsService = app.get('TestsService');
  } catch (e) {
    console.warn('TestsService not found, skipping test migration');
  }
  try {
    policiesService = app.get('PoliciesService');
  } catch (e) {
    console.warn('PoliciesService not found, skipping test migration');
  }

  try {
    console.log('='.repeat(60));
    console.log('Starting Migration Process');
    console.log('='.repeat(60));
    console.log('');

    // Migration 1: Tests → 1:1 Policy Relationship (if services available)
    if (testsService && policiesService) {
      console.log('Migration 1: Tests → 1:1 Policy Relationship');
      console.log('-'.repeat(60));
      await migrateTestsToPolicy1to1(testsService, policiesService);
      console.log('');
    } else {
      console.log('Migration 1: Tests → 1:1 Policy Relationship');
      console.log('-'.repeat(60));
      console.log('Skipped: TestsService or PoliciesService not available');
      console.log('');
    }

    console.log('='.repeat(60));
    console.log('All migrations completed successfully!');
    console.log('='.repeat(60));

    await app.close();
    process.exit(0);
  } catch (error) {
    console.error('Migration failed:', error);
    await app.close();
    process.exit(1);
  }
}

if (require.main === module) {
  bootstrap();
}
