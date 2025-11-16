/**
 * ABAC Access Control Test Suite
 * 
 * Demonstrates how to configure ABAC (Attribute-Based Access Control) test suites.
 * Note: Application name and contexts should be provided via runtime configuration.
 */

import { RuntimeTestConfig } from '../core/runtime-config';

/**
 * Creates an ABAC access control test suite.
 * Application name and contexts should be provided via runtimeConfig.
 */
export function createAbacAccessControlSuite(
  runtimeConfig?: RuntimeTestConfig
) {
  return {
    name: 'ABAC Access Control Tests',
    // Use runtime config application name if provided, otherwise use a default
    // In production, this should always come from runtime config
    application: runtimeConfig?.applicationName || 'default-app',
    team: 'default-team',
    testType: 'access-control' as const,
    userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
    resources: [
      {
        id: 'research-data-alpha',
        type: 'dataset',
        attributes: {
          sensitivity: 'confidential',
          department: 'Research',
          project: 'project-alpha',
          dataClassification: 'confidential',
          region: 'us-east',
        },
        sensitivity: 'confidential',
        abacAttributes: {
          dataClassification: 'confidential',
          department: 'Research',
          project: 'project-alpha',
          region: 'us-east',
          requiresCertification: 'data-science',
        },
      },
      {
        id: 'restricted-financial-data',
        type: 'dataset',
        attributes: {
          sensitivity: 'restricted',
          department: 'Finance',
          dataClassification: 'restricted',
        },
        sensitivity: 'restricted',
        abacAttributes: {
          dataClassification: 'restricted',
          department: 'Finance',
          minClearanceLevel: 'high',
        },
      },
      {
        id: 'public-research',
        type: 'report',
        attributes: {
          sensitivity: 'public',
          department: 'Research',
          dataClassification: 'public',
        },
        sensitivity: 'public',
        abacAttributes: {
          dataClassification: 'public',
          department: 'Research',
        },
      },
    ],
    // Contexts should be provided via runtime config, not hardcoded
    // This is a fallback for backward compatibility
    contexts: runtimeConfig?.contexts || [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'headquarters' },
      { ipAddress: '10.0.0.1', timeOfDay: '22:00', location: 'remote' },
      { ipAddress: '172.16.0.1', timeOfDay: '10:00', location: 'research-lab' },
    ],
    expectedDecisions: {
      // ABAC-based expectations
      'researcher-research-data-alpha': true, // Department match + project access
      'analyst-research-data-alpha': false, // No project access
      'viewer-restricted-financial-data': false, // Insufficient clearance
      'researcher-public-research': true, // Public resource
    },
    runtimeConfig,
  };
}

// Export a default instance for backward compatibility
// Note: This should not be used in production - always provide runtime config
export const abacAccessControlSuite = createAbacAccessControlSuite();

