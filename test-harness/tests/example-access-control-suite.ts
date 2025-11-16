/**
 * Example Access Control Test Suite
 * 
 * Demonstrates how to configure access control test suites
 */

import { AccessControlTestSuite } from '../core/types';

export const exampleAccessControlSuite: AccessControlTestSuite = {
  name: 'Research Tracker API Access Control Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  testType: 'access-control',
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
};

