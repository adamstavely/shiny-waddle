import { TestConfigurationType } from '../../test-configurations/entities/test-configuration.entity';

export type TestResultStatus = 'passed' | 'failed' | 'partial' | 'error';

export interface TestResultError {
  message: string;
  type: string;
  details?: any;
}

export interface TestResultEntity {
  id: string;
  applicationId: string;
  applicationName: string;
  testConfigurationId: string;
  testConfigurationName: string;
  testConfigurationType: TestConfigurationType;
  status: TestResultStatus;
  passed: boolean;
  buildId?: string;
  runId?: string;
  commitSha?: string;
  branch?: string;
  timestamp: Date;
  duration?: number; // in milliseconds
  result: any; // full test result object
  error?: TestResultError;
  metadata?: Record<string, any>;
  createdAt: Date;
}

export interface QueryFilters {
  applicationId?: string;
  testConfigurationId?: string;
  status?: TestResultStatus;
  branch?: string;
  limit?: number;
  offset?: number;
}

export interface DateRange {
  start: Date;
  end: Date;
}

export interface ComplianceMetrics {
  period: {
    start: Date;
    end: Date;
  };
  overall: {
    totalTests: number;
    passed: number;
    failed: number;
    partial: number;
    errors: number;
    passRate: number; // percentage
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
    lastFailure: Date;
    failureCount: number;
  }>;
  trends: Array<{
    period: string; // "2024-01-15" or "2024-W03"
    passRate: number;
    totalTests: number;
  }>;
}

