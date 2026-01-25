/**
 * Example Access Control Test Suite
 * 
 * Demonstrates how to configure access control test suites.
 * Note: Application name and contexts should be provided via runtime configuration.
 */

import { RuntimeTestConfig } from '../core/runtime-config';

/**
 * Creates an example access control test suite.
 * Application name and contexts should be provided via runtimeConfig.
 */
export function createExampleAccessControlSuite(
  runtimeConfig?: RuntimeTestConfig
) {
  return {
    name: 'Example Access Control Tests',
    // Use runtime config application name if provided, otherwise use a default
    // In production, this should always come from runtime config
    application: runtimeConfig?.applicationName || 'default-app',
    team: 'default-team',
    testType: 'access-control' as const,
    userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
    resources: [
      {
        id: 'reports',
        type: 'report',
        attributes: { sensitivity: 'internal' },
        sensitivity: 'internal',
      },
      {
        id: 'user-data',
        type: 'user',
        attributes: { sensitivity: 'confidential' },
        sensitivity: 'confidential',
      },
      {
        id: 'pii-data',
        type: 'pii',
        attributes: { sensitivity: 'restricted' },
        sensitivity: 'restricted',
      },
    ],
    // Contexts should be provided via runtime config, not hardcoded
    // This is a fallback for backward compatibility
    contexts: runtimeConfig?.contexts || [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'office' },
      { ipAddress: '10.0.0.1', timeOfDay: '22:00', location: 'remote' },
    ],
    expectedDecisions: {
      'admin-reports': true,
      'viewer-reports': true,
      'viewer-pii': false,
      'researcher-pii': true,
    },
    runtimeConfig,
  };
}

// Export a default instance for backward compatibility
// Note: This should not be used in production - always provide runtime config
export const exampleAccessControlSuite = createExampleAccessControlSuite();

