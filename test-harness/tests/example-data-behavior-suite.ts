/**
 * Example Data Behavior Test Suite
 * 
 * Demonstrates how to configure data behavior test suites
 */

import { DataBehaviorTestSuite } from '../core/types';

export const exampleDataBehaviorSuite: DataBehaviorTestSuite = {
  name: 'Research Tracker API Data Behavior Tests',
  application: 'research-tracker-api',
  team: 'research-platform',
  testType: 'data-behavior',
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
  ],
  contexts: [
    { ipAddress: '192.168.1.1', timeOfDay: '14:00', location: 'office' },
    { ipAddress: '10.0.0.1', timeOfDay: '22:00', location: 'remote' },
  ],
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
};

