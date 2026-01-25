export enum NotificationType {
  SCORE_DROP = 'score-drop',
  CRITICAL_FINDING = 'critical-finding',
  APPROVAL_REQUEST = 'approval-request',
  APPROVAL_STATUS_CHANGED = 'approval-status-changed',
  REMEDIATION_DEADLINE = 'remediation-deadline',
  REMEDIATION_OVERDUE = 'remediation-overdue',
  MILESTONE_DEADLINE = 'milestone-deadline',
  MILESTONE_OVERDUE = 'milestone-overdue',
}

export interface Notification {
  id: string;
  userId: string;
  type: NotificationType;
  title: string;
  message: string;
  read: boolean;
  createdAt: Date;
  metadata?: {
    findingId?: string;
    approvalRequestId?: string;
    scoreChange?: number;
    previousScore?: number;
    currentScore?: number;
    applicationId?: string;
    teamName?: string;
    trackingId?: string;
    violationId?: string;
    daysRemaining?: number;
    [key: string]: any; // Allow additional metadata fields
  };
}

export interface NotificationPreferences {
  userId: string;
  enabled: boolean;
  scoreDropThreshold: number; // Default: 5 points
  notifyOnCriticalFinding: boolean;
  notifyOnApprovalRequest: boolean;
  notifyOnApprovalStatusChanged: boolean;
  notifyOnRemediationDeadline?: boolean;
  notifyOnRemediationOverdue?: boolean;
  notifyOnMilestoneDeadline?: boolean;
  notifyOnMilestoneOverdue?: boolean;
}

