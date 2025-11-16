/**
 * Example Dataset Health Test Suite
 * 
 * Demonstrates how to configure dataset health test suites
 */

import { DatasetHealthTestSuite } from '../core/types';

export const exampleDatasetHealthSuite: DatasetHealthTestSuite = {
  name: 'Research Tracker API Dataset Health Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  testType: 'dataset-health',
  userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
  resources: [
    {
      id: 'masked-users',
      type: 'dataset',
      attributes: { sensitivity: 'internal' },
      sensitivity: 'internal',
    },
  ],
  contexts: [
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
};

