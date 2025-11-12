export enum SLASeverity {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
}

export enum SLAStatus {
  ON_TRACK = 'on_track',
  AT_RISK = 'at_risk',
  BREACHED = 'breached',
}

export interface SLAPolicy {
  id: string;
  name: string;
  description?: string;
  severity: SLASeverity;
  targetResolutionHours: number;
  warningThresholdHours: number;
  escalationRules: EscalationRule[];
  enabled: boolean;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface EscalationRule {
  id: string;
  triggerHours: number;
  action: 'notify' | 'assign' | 'escalate' | 'create-ticket';
  target: string;
  notificationChannels?: string[];
  message?: string;
}

export interface SLAViolation {
  id: string;
  violationId: string;
  slaPolicyId: string;
  status: SLAStatus;
  detectedAt: Date | string;
  targetResolutionAt: Date | string;
  warningThresholdAt: Date | string;
  resolvedAt?: Date | string;
  escalatedAt?: Date | string;
  escalationHistory: EscalationEvent[];
  currentAssignee?: string;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface EscalationEvent {
  id: string;
  type: 'warning' | 'escalation' | 'breach' | 'assignment';
  action: string;
  target: string;
  timestamp: Date | string;
  message?: string;
  metadata?: Record<string, any>;
}

export interface CreateSLAPolicyDto {
  name: string;
  description?: string;
  severity: SLASeverity;
  targetResolutionHours: number;
  warningThresholdHours: number;
  escalationRules: Omit<EscalationRule, 'id'>[];
  enabled: boolean;
}

