/**
 * ABAC Data Behavior Test Suite
 * 
 * Demonstrates how to configure ABAC data behavior test suites
 */

import { DataBehaviorTestSuite } from '../core/types';

export const abacDataBehaviorSuite: DataBehaviorTestSuite = {
  name: 'ABAC Data Behavior Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  testType: 'data-behavior',
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
  ],
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'headquarters' },
    { ipAddress: '10.0.0.1', timeOfDay: '22:00', location: 'remote' },
  ],
  testQueries: [
    {
      name: 'Access research data with department match',
      sql: 'SELECT * FROM research_data WHERE department = \'Research\'',
    },
    {
      name: 'Access restricted data without clearance',
      sql: 'SELECT * FROM financial_data WHERE classification = \'restricted\'',
    },
  ],
  allowedFields: {
    viewer: ['id', 'title'],
    analyst: ['id', 'title', 'summary'],
    researcher: ['id', 'title', 'summary', 'data'],
    admin: ['*'],
  },
  requiredFilters: {
    researcher: [
      { field: 'department', operator: '=', value: 'user_department' },
      { field: 'project', operator: 'IN', value: 'user_projects' },
    ],
  },
};

