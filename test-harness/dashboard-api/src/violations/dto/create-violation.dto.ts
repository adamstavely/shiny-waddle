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

export interface CreateViolationDto {
  title: string;
  description: string;
  type: ViolationType;
  severity: ViolationSeverity;
  status?: ViolationStatus;
  application?: string;
  team?: string;
  policyName?: string;
  policyId?: string;
  resource?: string;
  affectedResources?: string[];
  testResultId?: string;
  testResultDetails?: Record<string, any>;
  remediationSuggestions?: string[];
  detectedAt?: Date;
  assignedTo?: string;
  relatedViolationIds?: string[];
}

