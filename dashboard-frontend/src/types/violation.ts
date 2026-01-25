export enum ViolationSeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
}

export enum ViolationType {
  ACCESS_CONTROL = 'access-control',
  DATA_BEHAVIOR = 'data-behavior',
  CONTRACT = 'contract',
  DATASET_HEALTH = 'dataset-health',
  API_SECURITY = 'api-security',
  PIPELINE = 'pipeline',
  DISTRIBUTED_SYSTEM = 'distributed-system',
}

export enum ViolationStatus {
  OPEN = 'open',
  IN_PROGRESS = 'in-progress',
  RESOLVED = 'resolved',
  IGNORED = 'ignored',
}

export interface ViolationComment {
  id: string;
  author: string;
  content: string;
  createdAt: Date | string;
  updatedAt?: Date | string;
}

export interface RemediationEvent {
  id: string;
  type: 'assigned' | 'status-change' | 'comment' | 'remediation-started' | 'remediation-completed' | 'verified';
  description: string;
  actor: string;
  timestamp: Date | string;
  metadata?: Record<string, any>;
}

export interface ViolationEntity {
  id: string;
  title: string;
  description: string;
  type: ViolationType | string;
  severity: ViolationSeverity | string;
  status: ViolationStatus | string;
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
  detectedAt: Date | string;
  assignedTo?: string;
  relatedViolationIds?: string[];
  resolvedAt?: Date | string;
  resolvedBy?: string;
  ignoredAt?: Date | string;
  ignoredBy?: string;
  createdAt: Date | string;
  updatedAt: Date | string;
}

