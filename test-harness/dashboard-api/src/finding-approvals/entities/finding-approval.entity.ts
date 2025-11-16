export type ApprovalRequestType = 'risk-acceptance' | 'false-positive';

export type ApprovalRequestStatus = 'pending' | 'approved' | 'rejected' | 'cancelled';

export type ApproverRole = 'cyber-risk-manager' | 'data-steward';

export type ApprovalStatus = 'pending' | 'approved' | 'rejected';

export interface Approval {
  approverId: string;
  approverRole: ApproverRole;
  status: ApprovalStatus;
  approvedAt?: Date;
  comment?: string;
}

export type WorkflowType = 'parallel' | 'sequential' | 'conditional';

export interface ApprovalStage {
  stageId: string;
  stageName: string;
  order: number;
  requiredApprovers: ApproverRole[];
  approvals: Approval[];
  status: 'pending' | 'in-progress' | 'approved' | 'rejected';
  workflowType: WorkflowType; // How approvals work within this stage
  conditions?: {
    // Conditional routing conditions
    field: string;
    operator: 'equals' | 'greaterThan' | 'lessThan' | 'contains';
    value: any;
    nextStageId?: string; // Route to different stage if condition met
  }[];
  minApprovals?: number; // For parallel: minimum approvals needed
}

export interface FindingApprovalRequest {
  id: string;
  findingId: string;
  type: ApprovalRequestType;
  requestedBy: string;
  requestedAt: Date;
  reason: string;
  status: ApprovalRequestStatus;
  approvals: Approval[]; // Legacy - kept for backward compatibility
  requiredApprovers: ApproverRole[]; // Legacy - kept for backward compatibility
  stages?: ApprovalStage[]; // New multi-stage workflow
  currentStageId?: string; // Current stage being processed
  expiresAt?: Date;
  metadata?: {
    applicationId?: string;
    teamName?: string;
    findingTitle?: string;
    findingSeverity?: string;
  };
}

export interface ApprovalStageConfig {
  stageName: string;
  requiredApprovers: ApproverRole[];
  workflowType: WorkflowType;
  minApprovals?: number; // For parallel workflows
  conditions?: {
    field: string;
    operator: 'equals' | 'greaterThan' | 'lessThan' | 'contains';
    value: any;
    nextStageId?: string;
  }[];
}

export interface CreateApprovalRequestDto {
  findingId: string;
  type: ApprovalRequestType;
  reason: string;
  requestedBy: string;
  requiredApprovers?: ApproverRole[]; // Legacy - for simple workflows
  stages?: ApprovalStageConfig[]; // New - for multi-stage workflows
  expiresAt?: Date;
}

export interface ApproveRequestDto {
  approverId: string;
  approverRole: ApproverRole;
  comment?: string;
}

export interface RejectRequestDto {
  approverId: string;
  approverRole: ApproverRole;
  comment: string;
}

