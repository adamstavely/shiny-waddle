export type TestSuiteStatus = 'passing' | 'failing' | 'pending' | 'error';
export type TestSuiteSourceType = 'json' | 'typescript';

export interface TestSuiteEntity {
  id: string;
  name: string;
  applicationId: string;
  application?: string; // For display purposes
  team: string;
  status: TestSuiteStatus;
  lastRun?: Date;
  testCount: number;
  score: number;
  testType: string; // Required: single test type (e.g., 'access-control', 'data-behavior')
  domain: string; // Required: domain for this test suite
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  description?: string;
  sourceType?: TestSuiteSourceType; // 'json' for data/test-suites.json, 'typescript' for filesystem files
  sourcePath?: string; // Path to source file relative to project root
}

