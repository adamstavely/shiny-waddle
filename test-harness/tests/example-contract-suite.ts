/**
 * Example Contract Test Suite
 * 
 * Demonstrates how to configure contract test suites
 */

import { ContractTestSuite } from '../core/types';

export const exampleContractSuite: ContractTestSuite = {
  name: 'Research Tracker API Contract Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  testType: 'contract',
  userRoles: ['admin', 'researcher', 'analyst', 'viewer'],
  resources: [
    {
      id: 'reports',
      type: 'report',
      attributes: { sensitivity: 'internal' },
      sensitivity: 'internal',
    },
  ],
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'office' },
  ],
  contracts: [
    {
      name: 'No Raw Email Export',
      dataOwner: 'data-governance',
      requirements: [
        {
          id: 'no-email-export',
          description: 'No raw email addresses may be exported',
          type: 'export-restriction',
          rule: {
            restrictedFields: ['email'],
            requireMasking: true,
          },
          enforcement: 'hard',
        },
      ],
      machineReadable: true,
    },
    {
      name: 'Minimum Aggregation k=10',
      dataOwner: 'data-governance',
      requirements: [
        {
          id: 'min-aggregation',
          description: 'Queries must aggregate to minimum k=10 records',
          type: 'aggregation-requirement',
          rule: {
            minK: 10,
            requireAggregation: true,
          },
          enforcement: 'hard',
        },
      ],
      machineReadable: true,
    },
  ],
};

