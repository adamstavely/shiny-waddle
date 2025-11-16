/**
 * Example Dataset Health Test Suite
 * 
 * Demonstrates how to configure dataset health test suites.
 * Note: Application name and contexts should be provided via runtime configuration.
 */

import { RuntimeTestConfig } from '../core/runtime-config';

/**
 * Creates an example dataset health test suite.
 * Application name and contexts should be provided via runtimeConfig.
 */
export function createExampleDatasetHealthSuite(
  runtimeConfig?: RuntimeTestConfig
) {
  return {
    name: 'Example Dataset Health Tests',
    // Use runtime config application name if provided, otherwise use a default
    // In production, this should always come from runtime config
    application: runtimeConfig?.applicationName || 'default-app',
    team: 'default-team',
    testType: 'dataset-health' as const,
    userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
    resources: [
      {
        id: 'masked-users',
        type: 'dataset',
        attributes: { sensitivity: 'internal' },
        sensitivity: 'internal',
      },
    ],
    // Contexts should be provided via runtime config, not hardcoded
    // This is a fallback for backward compatibility
    contexts: runtimeConfig?.contexts || [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'office' },
    ],
    datasets: [
      {
        name: 'masked-users',
        type: 'masked',
        schema: {
          id: 'string',
          email_masked: 'string',
          name: 'string',
        },
        recordCount: 1000,
        piiFields: ['email_masked'],
      },
    ],
    privacyThresholds: [
      {
        metric: 'k-anonymity',
        threshold: 10,
        operator: '>=',
      },
    ],
    statisticalFidelityTargets: [
      {
        field: 'age',
        metric: 'mean',
        targetValue: 35.5,
        tolerance: 2.0,
      },
    ],
    runtimeConfig,
  };
}

// Export a default instance for backward compatibility
// Note: This should not be used in production - always provide runtime config
export const exampleDatasetHealthSuite = createExampleDatasetHealthSuite();

