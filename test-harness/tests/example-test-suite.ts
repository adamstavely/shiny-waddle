/**
 * Example Test Suite Configuration
 * 
 * Demonstrates how to configure test suites for compliance testing
 */

import { TestSuite } from '../core/types';

export const exampleTestSuite: TestSuite = {
  name: 'Research Tracker API Compliance Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  includeAccessControlTests: true,
  includeDataBehaviorTests: true,
  includeContractTests: true,
  includeDatasetHealthTests: true,
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
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'office' },
    { ipAddress: '10.0.0.1', timeOfDay: '22:00', location: 'remote' },
  ],
  expectedDecisions: {
    'admin-reports': true,
    'viewer-reports': true,
    'viewer-pii': false,
    'researcher-pii': true,
  },
  testQueries: [
    {
      name: 'Get all reports',
      sql: 'SELECT id, title, status FROM reports',
    },
    {
      name: 'Get user emails',
      sql: 'SELECT id, email FROM users',
    },
    {
      name: 'Get reports with user join',
      sql: 'SELECT r.*, u.email FROM reports r JOIN users u ON r.user_id = u.id',
    },
  ],
  allowedFields: {
    viewer: ['id', 'title', 'status'],
    analyst: ['id', 'title', 'status', 'created_at'],
    researcher: ['id', 'title', 'status', 'created_at', 'content'],
    admin: ['*'],
  },
  requiredFilters: {
    viewer: [{ field: 'workspace_id', operator: '=', value: 'user_workspace' }],
    analyst: [{ field: 'workspace_id', operator: '=', value: 'user_workspace' }],
  },
  disallowedJoins: {
    viewer: ['users', 'user_profiles'],
    analyst: ['user_profiles'],
  },
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

