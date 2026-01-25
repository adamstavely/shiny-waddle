/**
 * Example Test Suite
 * 
 * Default example test suite used as fallback when loading test suites
 */

import { TestSuite } from '../core/types';

export const exampleTestSuite: TestSuite = {
  id: 'example-suite',
  name: 'Example Test Suite',
  application: 'default-app',
  team: 'default-team',
  testType: 'access-control',
  domain: 'api_security',
  testIds: [],
  description: 'Example test suite for demonstration purposes',
  enabled: true,
  createdAt: new Date(),
  updatedAt: new Date(),
};
