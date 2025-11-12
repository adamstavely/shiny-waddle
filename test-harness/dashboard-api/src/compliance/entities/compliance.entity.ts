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
  controlId: string; // e.g., "AC-1", "AC-2", "SI-2"
  title: string;
  description: string;
  family?: string; // e.g., "Access Control", "System and Information Integrity"
  priority: ControlSeverity;
  baseline?: string[]; // e.g., ["LOW", "MODERATE", "HIGH"]
  relatedControls?: string[]; // Related control IDs
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
  violations: string[]; // Violation IDs that affect this control
  policies: string[]; // Policy IDs that implement this control
  tests: string[]; // Test IDs that validate this control
  lastAssessed?: Date;
  assessedBy?: string;
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ComplianceEvidence {
  id: string;
  type: 'policy' | 'test-result' | 'documentation' | 'configuration' | 'audit-log' | 'other';
  title: string;
  description?: string;
  reference: string; // URL, file path, or ID reference
  collectedAt: Date;
  collectedBy: string;
  metadata?: Record<string, any>;
}

export interface ComplianceAssessment {
  id: string;
  framework: ComplianceFramework;
  name: string;
  description?: string;
  assessedAt: Date;
  assessedBy: string;
  mappings: ComplianceMapping[];
  summary: ComplianceSummary;
  createdAt: Date;
  updatedAt: Date;
}

export interface ComplianceSummary {
  totalControls: number;
  compliant: number;
  nonCompliant: number;
  partiallyCompliant: number;
  notApplicable: number;
  notAssessed: number;
  compliancePercentage: number;
  criticalGaps: string[]; // Control IDs with critical non-compliance
  highPriorityGaps: string[]; // Control IDs with high priority gaps
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
  targetDate?: Date;
}

export interface ComplianceRoadmap {
  id: string;
  framework: ComplianceFramework;
  name: string;
  description?: string;
  gaps: ComplianceGap[];
  targetComplianceDate?: Date;
  milestones: RoadmapMilestone[];
  createdAt: Date;
  updatedAt: Date;
}

export interface RoadmapMilestone {
  id: string;
  name: string;
  description?: string;
  controlIds: string[];
  targetDate: Date;
  completedAt?: Date;
  status: 'pending' | 'in-progress' | 'completed' | 'overdue';
}

export interface CreateComplianceMappingDto {
  framework: ComplianceFramework;
  controlId: string;
  status: ControlStatus;
  violations?: string[];
  policies?: string[];
  tests?: string[];
  notes?: string;
}

export interface CreateComplianceAssessmentDto {
  framework: ComplianceFramework;
  name: string;
  description?: string;
  mappings: Omit<ComplianceMapping, 'id' | 'createdAt' | 'updatedAt'>[];
}

