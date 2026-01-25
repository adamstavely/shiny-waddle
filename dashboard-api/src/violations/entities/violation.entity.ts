import { ViolationSeverity, ViolationType, ViolationStatus } from '../dto/create-violation.dto';

export interface ViolationEntity {
  id: string;
  title: string;
  description: string;
  type: ViolationType;
  severity: ViolationSeverity;
  status: ViolationStatus;
  application?: string;
  team?: string;
  policyName?: string;
  policyId?: string;
  resource?: string;
  affectedResources?: string[];
  testResultId?: string;
  testResultDetails?: Record<string, any>;
  remediationSuggestions?: string[];
  remediationStatus?: string;
  remediationTimeline?: RemediationEvent[];
  verificationTestIds?: string[];
  comments?: ViolationComment[];
  detectedAt: Date;
  assignedTo?: string;
  relatedViolationIds?: string[];
  resolvedAt?: Date;
  resolvedBy?: string;
  ignoredAt?: Date;
  ignoredBy?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ViolationComment {
  id: string;
  author: string;
  content: string;
  createdAt: Date;
  updatedAt?: Date;
}

export interface RemediationEvent {
  id: string;
  type: 'assigned' | 'status-change' | 'comment' | 'remediation-started' | 'remediation-completed' | 'verified';
  description: string;
  actor: string;
  timestamp: Date;
  metadata?: Record<string, any>;
}

