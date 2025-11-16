/**
 * ABAC Attribute Validation Test Suite
 * 
 * Tests ABAC attribute definitions, schemas, sources, freshness, and access controls.
 * Note: Application name and contexts should be provided via runtime configuration.
 */

import { RuntimeTestConfig } from '../core/runtime-config';
import { AccessControlTestSuiteConfig } from '../core/types';

/**
 * Creates an ABAC attribute validation test suite.
 * Application name and contexts should be provided via runtimeConfig.
 */
export function createAbacAttributeValidationSuite(
  runtimeConfig?: RuntimeTestConfig
): AccessControlTestSuiteConfig {
  return {
    name: 'ABAC Attribute Validation Tests',
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
          sensitivity: 'internal',
        },
        sensitivity: 'internal',
      },
    ],
    // Contexts should be provided via runtime config, not hardcoded
    // This is a fallback for backward compatibility
    contexts: runtimeConfig?.contexts || [
      { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'headquarters' },
    ],
    abacCorrectnessConfig: {
      attributes: [
        {
          name: 'clearanceLevel',
          type: 'string',
          source: 'ldap',
          validation: [
            {
              type: 'enum',
              value: ['low', 'medium', 'high', 'top-secret'],
            },
          ],
          freshness: {
            maxAge: 24,
            unit: 'hours',
          },
        },
        {
          name: 'department',
          type: 'string',
          source: 'ldap',
          validation: [
            {
              type: 'required',
            },
          ],
        },
        {
          name: 'projectAccess',
          type: 'array',
          source: 'database',
          validation: [
            {
              type: 'required',
            },
          ],
        },
      ],
    },
    runtimeConfig,
  };
}

// Export a default instance for backward compatibility
// Note: This should not be used in production - always provide runtime config
export const abacAttributeValidationSuite = createAbacAttributeValidationSuite();

