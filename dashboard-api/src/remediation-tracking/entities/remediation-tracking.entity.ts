export interface RemediationTracking {
  id: string;
  violationId: string;
  
  // Progress Tracking
  status: 'not-started' | 'in-progress' | 'completed' | 'failed' | 'cancelled' | 'overdue';
  progress: number; // 0-100
  milestones: RemediationMilestone[];
  currentStep?: string;
  
  // Time Tracking
  startedAt?: Date;
  completedAt?: Date;
  targetDate?: Date; // Deadline for remediation
  timeToRemediation?: number; // in hours
  timeToStart?: number; // hours from detection to start
  
  // Effectiveness Tracking
  effectiveness: 'effective' | 'ineffective' | 'unknown' | 'pending';
  effectivenessReason?: string;
  verifiedAt?: Date;
  verifiedBy?: string;
  verificationTestId?: string;
  
  // Recurrence Tracking
  isRecurrence: boolean;
  originalViolationId?: string; // If this is a recurrence
  recurrenceCount: number; // How many times this violation has recurred
  recurrenceHistory: RecurrenceEvent[];
  
  // Metadata
  assignedTo?: string;
  remediationMethod?: string; // 'manual' | 'automated' | 'patch' | 'config-change'
  remediationSteps: RemediationStep[];
  notes?: string;
  
  createdAt: Date;
  updatedAt: Date;
}

export interface RemediationMilestone {
  id: string;
  name: string;
  description?: string;
  status: 'pending' | 'in-progress' | 'completed' | 'skipped';
  completedAt?: Date;
  targetDate?: Date; // Deadline for milestone
  estimatedHours?: number;
  actualHours?: number;
}

export interface RemediationStep {
  id: string;
  order: number;
  description: string;
  status: 'pending' | 'in-progress' | 'completed' | 'skipped';
  startedAt?: Date;
  completedAt?: Date;
  duration?: number; // in minutes
  actor?: string;
  notes?: string;
}

export interface RecurrenceEvent {
  id: string;
  violationId: string;
  detectedAt: Date;
  resolvedAt?: Date;
  timeToRemediation?: number; // hours
  remediationMethod?: string;
}

export interface RemediationMetrics {
  violationId: string;
  averageTimeToRemediation: number; // hours
  averageTimeToStart: number; // hours
  effectivenessRate: number; // percentage
  recurrenceRate: number; // percentage
  totalRemediations: number;
  successfulRemediations: number;
  failedRemediations: number;
}

export interface CreateRemediationTrackingDto {
  violationId: string;
  assignedTo?: string;
  remediationMethod?: string;
  milestones?: Omit<RemediationMilestone, 'id'>[];
  remediationSteps?: Omit<RemediationStep, 'id'>[];
}

