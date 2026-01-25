/**
 * Migration: Convert Platform Instances to Applications
 * 
 * This migration converts existing Platform Instances into Applications
 * that can be tested using Test Suites (migrated from Baselines).
 */

import { Application, ApplicationInfrastructure, ApplicationType, ApplicationStatus, PlatformInstanceInfrastructure } from '../applications/entities/application.entity';
import { PlatformInstance } from './baseline-to-test-suite.migration';

/**
 * Convert Platform Instance to Application
 */
export async function migrateInstanceToApplication(
  instance: PlatformInstance,
  testSuiteId: string // The Test Suite ID (from migrated baseline)
): Promise<Application> {
  // Create platform-specific infrastructure
  const platformInfrastructure: ApplicationInfrastructure = {
    platformInstance: {
      platform: instance.platform,
      connection: instance.connection,
      testSuiteId: testSuiteId, // Reference to the Test Suite (migrated baseline)
    },
  };
  
  // Create Application
  const application: Application = {
    id: instance.id, // Keep same ID for reference continuity
    name: instance.name,
    type: 'platform' as ApplicationType,
    status: (instance.status === 'healthy' ? 'active' : 'inactive') as ApplicationStatus,
    description: `Platform Instance: ${instance.name} (${instance.platform})`,
    team: 'platform-team',
    infrastructure: platformInfrastructure,
    registeredAt: instance.createdAt ? new Date(instance.createdAt) : new Date(),
    updatedAt: instance.updatedAt ? new Date(instance.updatedAt) : new Date(),
    lastTestAt: instance.lastValidatedAt ? new Date(instance.lastValidatedAt) : undefined,
    baseUrl: instance.connection?.endpoint,
  };
  
  return application;
}

/**
 * Batch migrate multiple instances
 */
export async function migrateInstancesToApplications(
  instances: PlatformInstance[],
  baselineToTestSuiteMap: Map<string, string> // Maps baselineId -> testSuiteId
): Promise<Application[]> {
  const applications: Application[] = [];
  
  for (const instance of instances) {
    const testSuiteId = baselineToTestSuiteMap.get(instance.baselineId);
    
    if (!testSuiteId) {
      console.warn(`No test suite found for baseline ${instance.baselineId}, skipping instance ${instance.id}`);
      continue;
    }
    
    const application = await migrateInstanceToApplication(instance, testSuiteId);
    applications.push(application);
  }
  
  return applications;
}
