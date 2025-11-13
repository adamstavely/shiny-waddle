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

export interface FindingApprovalRequest {
  id: string;
  findingId: string;
  type: ApprovalRequestType;
  requestedBy: string;
  requestedAt: Date;
  reason: string;
  status: ApprovalRequestStatus;
  approvals: Approval[];
  requiredApprovers: ApproverRole[];
  expiresAt?: Date;
  metadata?: {
    applicationId?: string;
    teamName?: string;
    findingTitle?: string;
    findingSeverity?: string;
  };
}

export interface CreateApprovalRequestDto {
  findingId: string;
  type: ApprovalRequestType;
  reason: string;
  requestedBy: string;
  requiredApprovers?: ApproverRole[];
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

