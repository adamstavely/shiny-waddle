import { ValidationTargetType, ValidationTargetStatus } from '../dto/create-validation-target.dto';

export interface ValidationTargetEntity {
  id: string;
  name: string;
  type: ValidationTargetType;
  description?: string;
  connectionConfig: Record<string, any>;
  status: ValidationTargetStatus;
  ruleIds: string[];
  lastValidationAt?: Date;
  nextScheduledRun?: Date;
  createdAt: Date;
  updatedAt: Date;
}

export interface ValidationRuleEntity {
  id: string;
  name: string;
  description: string;
  targetId: string;
  severity: string;
  ruleConfig: Record<string, any>;
  checkType?: string;
  conditions?: Record<string, any>;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface ValidationResultEntity {
  id: string;
  targetId: string;
  ruleId: string;
  status: 'passed' | 'failed' | 'warning';
  message: string;
  details?: Record<string, any>;
  timestamp: Date;
}

