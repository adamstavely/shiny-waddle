export enum ComplianceFramework {
  NIST_800_53_REV_4 = 'nist_800_53_rev_4',
  NIST_800_53_REV_5 = 'nist_800_53_rev_5',
  SOC_2 = 'soc_2',
  PCI_DSS = 'pci_dss',
  HIPAA = 'hipaa',
  GDPR = 'gdpr',
  ISO_27001 = 'iso_27001',
  NIST_CSF = 'nist_csf',
  OWASP_ASVS = 'owasp_asvs',
}

export enum ControlStatus {
  COMPLIANT = 'compliant',
  NON_COMPLIANT = 'non_compliant',
  PARTIALLY_COMPLIANT = 'partially_compliant',
  NOT_APPLICABLE = 'not_applicable',
  NOT_ASSESSED = 'not_assessed',
}

export enum ControlSeverity {
  LOW = 'low',
  MODERATE = 'moderate',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export interface ComplianceControl {
  id: string;
  framework: ComplianceFramework;
  controlId: string;
  title: string;
  description: string;
  family?: string;
  priority: ControlSeverity;
  baseline?: string[];
  relatedControls?: string[];
  implementationGuidance?: string;
  assessmentGuidance?: string;
  references?: string[];
  metadata?: Record<string, any>;
}

export interface ComplianceMapping {
  id: string;
  framework: ComplianceFramework;
  controlId: string;
  status: ControlStatus;
  evidence: ComplianceEvidence[];
  violations: string[];
  policies: string[];
  tests: string[];
  lastAssessed?: Date | string;
  assessedBy?: string;
  notes?: string;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface ComplianceEvidence {
  id: string;
  type: 'policy' | 'test-result' | 'documentation' | 'configuration' | 'audit-log' | 'other';
  title: string;
  description?: string;
  reference: string;
  collectedAt: Date | string;
  collectedBy: string;
  metadata?: Record<string, any>;
}

export interface ComplianceAssessment {
  id: string;
  framework: ComplianceFramework;
  name: string;
  description?: string;
  assessedAt: Date | string;
  assessedBy: string;
  mappings: ComplianceMapping[];
  summary: ComplianceSummary;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface ComplianceSummary {
  totalControls: number;
  compliant: number;
  nonCompliant: number;
  partiallyCompliant: number;
  notApplicable: number;
  notAssessed: number;
  compliancePercentage: number;
  criticalGaps: string[];
  highPriorityGaps: string[];
}

export interface ComplianceGap {
  controlId: string;
  controlTitle: string;
  status: ControlStatus;
  priority: ControlSeverity;
  violations: string[];
  remediationSteps: string[];
  estimatedEffort?: 'low' | 'medium' | 'high';
  assignedTo?: string;
  targetDate?: Date | string;
}

export interface ComplianceRoadmap {
  id: string;
  framework: ComplianceFramework;
  name: string;
  description?: string;
  gaps: ComplianceGap[];
  targetComplianceDate?: Date | string;
  milestones: RoadmapMilestone[];
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface RoadmapMilestone {
  id: string;
  name: string;
  description?: string;
  controlIds: string[];
  targetDate: Date | string;
  completedAt?: Date | string;
  status: 'pending' | 'in-progress' | 'completed' | 'overdue';
}

