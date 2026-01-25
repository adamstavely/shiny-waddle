export type TestResultStatus = 'passed' | 'failed' | 'partial' | 'error';

export interface TestResultError {
  message: string;
  type: string;
  details?: any;
}

export interface TestResult {
  id: string;
  applicationId: string;
  applicationName: string;
  testConfigurationId: string;
  testConfigurationName: string;
  testConfigurationType: string;
  status: TestResultStatus;
  passed: boolean;
  buildId?: string;
  runId?: string;
  commitSha?: string;
  branch?: string;
  timestamp: string | Date;
  duration?: number;
  result: any;
  error?: TestResultError;
  metadata?: Record<string, any>;
  createdAt: string | Date;
}

export interface ComplianceMetrics {
  period: {
    start: string | Date;
    end: string | Date;
  };
  overall: {
    totalTests: number;
    passed: number;
    failed: number;
    partial: number;
    errors: number;
    passRate: number;
    averageDuration: number;
    trend: 'improving' | 'declining' | 'stable';
  };
  byTestConfiguration: {
    [configId: string]: {
      configName: string;
      configType: string;
      totalTests: number;
      passed: number;
      failed: number;
      passRate: number;
    };
  };
  failingTests: Array<{
    configId: string;
    configName: string;
    lastFailure: string | Date;
    failureCount: number;
  }>;
  trends: Array<{
    period: string;
    passRate: number;
    totalTests: number;
  }>;
}

