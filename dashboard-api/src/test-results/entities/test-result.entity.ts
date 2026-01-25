import { TestConfigurationType } from '../../test-configurations/entities/test-configuration.entity';

export type TestResultStatus = 'passed' | 'failed' | 'partial' | 'error';

export interface TestResultError {
  message: string;
  type: string;
  details?: any;
}

export interface RiskAcceptance {
  accepted: boolean;
  reason?: string;
  approver?: string;
  approvedAt?: Date;
  expirationDate?: Date;
  ticketLink?: string;
  rejected?: boolean;
  rejectionReason?: string;
}

export interface RemediationTracking {
  status?: 'not-started' | 'in-progress' | 'completed';
  ticketLink?: string;
  assignedTo?: string;
  targetDate?: Date;
  notes?: string;
  progress?: number; // 0-100
  steps?: Array<{
    step: string;
    status: 'pending' | 'in-progress' | 'completed';
    completedAt?: Date;
  }>;
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
  riskAcceptance?: RiskAcceptance;
  remediation?: RemediationTracking;
  createdAt: Date;
}

export interface QueryFilters {
  applicationId?: string;
  testConfigurationId?: string;
  testHarnessId?: string;
  testBatteryId?: string;
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

