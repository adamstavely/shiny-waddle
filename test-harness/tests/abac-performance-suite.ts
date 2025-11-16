/**
 * ABAC Performance Test Suite
 * 
 * Tests ABAC evaluation latency, caching, attribute lookup performance, and load performance.
 * Note: Application name and contexts should be provided via runtime configuration.
 */

import { RuntimeTestConfig } from '../core/runtime-config';
import { AccessControlTestSuiteConfig } from '../core/types';

/**
 * Creates an ABAC performance test suite.
 * Application name and contexts should be provided via runtimeConfig.
 */
export function createAbacPerformanceSuite(
  runtimeConfig?: RuntimeTestConfig
): AccessControlTestSuiteConfig {
  return {
    name: 'ABAC Performance Tests',
    // Use runtime config application name if provided, otherwise use a default
    // In production, this should always come from runtime config
    application: runtimeConfig?.applicationName || 'default-app',
    team: 'default-team',
    testType: 'access-control',
    userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
    resources: [
      {
        id: 'test-resource',
        type: 'dataset',
        attributes: {
          sensitivity: 'confidential',
          department: 'Research',
        },
        sensitivity: 'confidential',
        abacAttributes: {
          dataClassification: 'confidential',
          department: 'Research',
        },
      },
    ],
    // Contexts should be provided via runtime config, not hardcoded
    // This is a fallback for backward compatibility
    contexts: runtimeConfig?.contexts || [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'headquarters' },
    ],
    abacCorrectnessConfig: {
      policies: [], // Policies will be loaded from the application's policy configuration
      performanceConfig: {
        policies: [], // Will be populated from abacCorrectnessConfig.policies
        testRequests: [
          {
            subject: {
              id: 'test-user-1',
              attributes: {
                role: 'researcher',
                department: 'Research',
                clearanceLevel: 'high',
              },
            },
            resource: {
              id: 'test-resource',
              type: 'dataset',
              attributes: {
                department: 'Research',
                dataClassification: 'confidential',
              },
            },
            context: {
              ipAddress: '192.168.1.1',
              timeOfDay: '14:00',
              location: 'headquarters',
            },
            action: 'read',
          },
        ],
        loadConfig: {
          concurrentRequests: 10,
          duration: 5000, // 5 seconds
        },
      },
    },
    runtimeConfig,
  };
}

// Export a default instance for backward compatibility
// Note: This should not be used in production - always provide runtime config
export const abacPerformanceSuite = createAbacPerformanceSuite();

