import { TestExecutionStatus, AuditLogType, ActivityType } from '../entities/history.entity';

export interface CreateTestExecutionDto {
  suiteName: string;
  suiteId?: string;
  application?: string;
  team?: string;
  status: TestExecutionStatus;
  testCount: number;
  passedCount: number;
  failedCount: number;
  score: number;
  duration?: number;
  testResults?: any[];
  metadata?: Record<string, any>;
}

export interface CreateAuditLogDto {
  type: AuditLogType;
  action: string;
  description: string;
  user: string;
  application?: string;
  team?: string;
  metadata?: Record<string, any>;
  resourceId?: string;
  resourceType?: string;
  oldValue?: any;
  newValue?: any;
}

export interface CreateActivityDto {
  type: ActivityType;
  user: string;
  action: string;
  details: string;
  application?: string;
  team?: string;
  resourceId?: string;
  resourceType?: string;
  metadata?: Record<string, any>;
}

