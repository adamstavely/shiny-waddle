export enum NotificationType {
  SCORE_DROP = 'score-drop',
  CRITICAL_FINDING = 'critical-finding',
  APPROVAL_REQUEST = 'approval-request',
  APPROVAL_STATUS_CHANGED = 'approval-status-changed',
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
  };
}

export interface NotificationPreferences {
  userId: string;
  enabled: boolean;
  scoreDropThreshold: number; // Default: 5 points
  notifyOnCriticalFinding: boolean;
  notifyOnApprovalRequest: boolean;
  notifyOnApprovalStatusChanged: boolean;
}

