/**
 * ABAC Access Control Test Suite
 * 
 * Demonstrates how to configure ABAC (Attribute-Based Access Control) test suites
 */

import { AccessControlTestSuite } from '../core/types';

export const abacAccessControlSuite: AccessControlTestSuite = {
  name: 'ABAC Access Control Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  testType: 'access-control',
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
  contexts: [
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
};

