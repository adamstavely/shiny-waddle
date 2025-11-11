export enum TestExecutionStatus {
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  CANCELLED = 'cancelled',
}

export enum AuditLogType {
  POLICY_CHANGE = 'policy-change',
  TEST_SUITE_CHANGE = 'test-suite-change',
  REPORT_GENERATION = 'report-generation',
  VIOLATION_RESOLUTION = 'violation-resolution',
  USER_ACTION = 'user-action',
  SYSTEM_EVENT = 'system-event',
}

export enum ActivityType {
  TEST_EXECUTION = 'test-execution',
  POLICY_UPDATE = 'policy-update',
  REPORT_GENERATION = 'report-generation',
  VIOLATION_RESOLUTION = 'violation-resolution',
  TEST_SUITE_CREATED = 'test-suite-created',
  TEST_SUITE_UPDATED = 'test-suite-updated',
}

export interface TestExecutionEntity {
  id: string;
  suiteName: string;
  suiteId?: string;
  application?: string;
  team?: string;
  status: TestExecutionStatus;
  timestamp: Date;
  testCount: number;
  passedCount: number;
  failedCount: number;
  score: number;
  duration?: number; // in milliseconds
  testResults?: TestResult[];
  metadata?: Record<string, any>;
}

export interface TestResult {
  id: string;
  testName: string;
  status: 'passed' | 'failed' | 'skipped';
  duration: number;
  error?: string;
  details?: Record<string, any>;
}

export interface AuditLogEntity {
  id: string;
  type: AuditLogType;
  action: string;
  description: string;
  user: string;
  application?: string;
  team?: string;
  timestamp: Date;
  metadata?: Record<string, any>;
  resourceId?: string;
  resourceType?: string;
  oldValue?: any;
  newValue?: any;
}

export interface ActivityEntity {
  id: string;
  type: ActivityType;
  user: string;
  action: string;
  details: string;
  timestamp: Date;
  application?: string;
  team?: string;
  resourceId?: string;
  resourceType?: string;
  metadata?: Record<string, any>;
}

