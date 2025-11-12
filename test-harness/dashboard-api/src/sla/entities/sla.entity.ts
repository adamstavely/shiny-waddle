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
  targetResolutionHours: number; // Target time to resolution in hours
  warningThresholdHours: number; // Hours before breach to warn
  escalationRules: EscalationRule[];
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface EscalationRule {
  id: string;
  triggerHours: number; // Hours after violation detection
  action: 'notify' | 'assign' | 'escalate' | 'create-ticket';
  target: string; // User, team, or integration ID
  notificationChannels?: string[]; // email, slack, etc.
  message?: string;
}

export interface SLAViolation {
  id: string;
  violationId: string;
  slaPolicyId: string;
  status: SLAStatus;
  detectedAt: Date;
  targetResolutionAt: Date;
  warningThresholdAt: Date;
  resolvedAt?: Date;
  escalatedAt?: Date;
  escalationHistory: EscalationEvent[];
  currentAssignee?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface EscalationEvent {
  id: string;
  type: 'warning' | 'escalation' | 'breach' | 'assignment';
  action: string;
  target: string;
  timestamp: Date;
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

