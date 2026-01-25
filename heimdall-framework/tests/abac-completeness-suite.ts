/**
 * ABAC Policy Completeness Test Suite
 * 
 * Tests ABAC policy coverage for resource types, user roles, actions, and edge cases.
 * Note: Application name and contexts should be provided via runtime configuration.
 */

import { RuntimeTestConfig } from '../core/runtime-config';
import { AccessControlTestSuiteConfig } from '../core/types';

/**
 * Creates an ABAC policy completeness test suite.
 * Application name and contexts should be provided via runtimeConfig.
 */
export function createAbacCompletenessSuite(
  runtimeConfig?: RuntimeTestConfig
): AccessControlTestSuiteConfig {
  return {
    name: 'ABAC Policy Completeness Tests',
    // Use runtime config application name if provided, otherwise use a default
    // In production, this should always come from runtime config
    application: runtimeConfig?.applicationName || 'default-app',
    team: 'default-team',
    testType: 'access-control',
    userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
    resources: [
      {
        id: 'dataset-resource',
        type: 'dataset',
        attributes: {
          sensitivity: 'confidential',
        },
        sensitivity: 'confidential',
      },
      {
        id: 'report-resource',
        type: 'report',
        attributes: {
          sensitivity: 'internal',
        },
        sensitivity: 'internal',
      },
      {
        id: 'database-resource',
        type: 'database',
        attributes: {
          sensitivity: 'restricted',
        },
        sensitivity: 'restricted',
      },
    ],
    // Contexts should be provided via runtime config, not hardcoded
    // This is a fallback for backward compatibility
    contexts: runtimeConfig?.contexts || [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'headquarters' },
    ],
    abacCorrectnessConfig: {
      resourceTypes: ['dataset', 'report', 'database'],
      userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
      policies: [], // Policies will be loaded from the application's policy configuration
    },
    runtimeConfig,
  };
}

// Export a default instance for backward compatibility
// Note: This should not be used in production - always provide runtime config
export const abacCompletenessSuite = createAbacCompletenessSuite();

