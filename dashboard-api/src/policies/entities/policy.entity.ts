import { PolicyType, PolicyStatus, PolicyEffect, RBACRule, ABACCondition } from '../dto/create-policy.dto';

export interface PolicyVersion {
  version: string;
  status: PolicyStatus;
  date: Date;
  author?: string;
  changes: Array<{
    type: 'added' | 'changed' | 'fixed' | 'removed' | 'deprecated';
    description: string;
  }>;
  notes?: string;
}

export interface PolicyAuditLog {
  id: string;
  policyId: string;
  action: 'created' | 'updated' | 'deleted' | 'deployed' | 'rolled_back' | 'status_changed';
  userId?: string;
  timestamp: Date;
  details?: Record<string, any>;
  previousVersion?: string;
  newVersion?: string;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  type: PolicyType;
  version: string;
  status: PolicyStatus;
  effect?: PolicyEffect;
  priority?: number;
  rules?: RBACRule[];
  conditions?: ABACCondition[];
  applicationId?: string;
  versions: PolicyVersion[];
  createdAt: Date;
  updatedAt: Date;
  lastDeployedAt?: Date;
  deployedVersion?: string;
  ruleCount?: number;
  testCoverage?: string;
  violationsDetected?: number;
}

