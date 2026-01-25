/**
 * Audit & Evidence Service
 * 
 * Comprehensive audit trail, evidence collection, compliance reports, and attestation workflows
 */

import * as fs from 'fs/promises';
import * as path from 'path';

export interface AuditEvent {
  id: string;
  timestamp: Date;
  eventType: 'policy_change' | 'test_execution' | 'compliance_check' | 'attestation' | 'evidence_collection' | 'user_action' | 'system_event';
  actor: {
    type: 'user' | 'system' | 'service';
    id: string;
    name?: string;
  };
  resource: {
    type: string;
    id: string;
    name?: string;
  };
  action: string;
  outcome: 'success' | 'failure' | 'partial';
  details: Record<string, any>;
  metadata?: Record<string, any>;
}

export interface Evidence {
  id: string;
  type: 'policy' | 'test-result' | 'documentation' | 'configuration' | 'audit-log' | 'screenshot' | 'log-file' | 'api-response' | 'other';
  title: string;
  description?: string;
  reference: string; // URL, file path, or ID reference
  collectedAt: Date;
  collectedBy: string;
  collectedByType: 'user' | 'system' | 'automated';
  metadata?: Record<string, any>;
  tags?: string[];
  complianceFrameworks?: string[]; // e.g., ['NIST-800-53', 'SOC-2']
  relatedControls?: string[]; // Control IDs
  expirationDate?: Date;
}

export interface ComplianceReport {
  id: string;
  title: string;
  framework: string;
  generatedAt: Date;
  generatedBy: string;
  period: {
    start: Date;
    end: Date;
  };
  summary: {
    totalControls: number;
    compliantControls: number;
    nonCompliantControls: number;
    notAssessedControls: number;
    complianceScore: number;
  };
  controls: Array<{
    controlId: string;
    controlTitle: string;
    status: 'compliant' | 'non-compliant' | 'not-assessed' | 'partial';
    evidence: string[]; // Evidence IDs
    findings: string[]; // Finding IDs
    notes?: string;
  }>;
  evidence: Evidence[];
  recommendations: Array<{
    priority: 'high' | 'medium' | 'low';
    controlId: string;
    description: string;
    remediationSteps: string[];
  }>;
}

export interface Attestation {
  id: string;
  title: string;
  description?: string;
  framework: string;
  controls: string[]; // Control IDs
  attestedBy: {
    id: string;
    name: string;
    role: string;
    email?: string;
  };
  attestedAt: Date;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  evidence: string[]; // Evidence IDs
  approver?: {
    id: string;
    name: string;
    role: string;
    approvedAt?: Date;
    notes?: string;
  };
  expirationDate?: Date;
  metadata?: Record<string, any>;
}

export interface AttestationWorkflow {
  id: string;
  name: string;
  description?: string;
  framework: string;
  steps: Array<{
    stepNumber: number;
    name: string;
    description?: string;
    requiredRole?: string;
    requiredApproval?: boolean;
    evidenceRequired?: boolean;
    completed: boolean;
    completedBy?: string;
    completedAt?: Date;
  }>;
  currentStep: number;
  status: 'draft' | 'in-progress' | 'pending-approval' | 'approved' | 'rejected' | 'expired';
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export class AuditEvidenceService {
  private auditLogDir: string;
  private evidenceDir: string;
  private reportsDir: string;
  private attestationsDir: string;

  constructor(
    baseDir: string = './data',
    auditLogDir?: string,
    evidenceDir?: string,
    reportsDir?: string,
    attestationsDir?: string
  ) {
    this.auditLogDir = auditLogDir || path.join(baseDir, 'audit-logs');
    this.evidenceDir = evidenceDir || path.join(baseDir, 'evidence');
    this.reportsDir = reportsDir || path.join(baseDir, 'compliance-reports');
    this.attestationsDir = attestationsDir || path.join(baseDir, 'attestations');
  }

  /**
   * Record audit event
   */
  async recordEvent(event: Omit<AuditEvent, 'id' | 'timestamp'>): Promise<AuditEvent> {
    const auditEvent: AuditEvent = {
      ...event,
      id: this.generateId(),
      timestamp: new Date(),
    };

    await this.saveAuditEvent(auditEvent);
    return auditEvent;
  }

  /**
   * Get audit trail
   */
  async getAuditTrail(filters?: {
    eventType?: AuditEvent['eventType'][];
    actorId?: string;
    resourceType?: string;
    resourceId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<AuditEvent[]> {
    const events = await this.loadAuditEvents();

    let filtered = events;

    if (filters?.eventType) {
      filtered = filtered.filter(e => filters.eventType!.includes(e.eventType));
    }
    if (filters?.actorId) {
      filtered = filtered.filter(e => e.actor.id === filters.actorId);
    }
    if (filters?.resourceType) {
      filtered = filtered.filter(e => e.resource.type === filters.resourceType);
    }
    if (filters?.resourceId) {
      filtered = filtered.filter(e => e.resource.id === filters.resourceId);
    }
    if (filters?.startDate) {
      filtered = filtered.filter(e => e.timestamp >= filters.startDate!);
    }
    if (filters?.endDate) {
      filtered = filtered.filter(e => e.timestamp <= filters.endDate!);
    }

    // Sort by timestamp descending
    filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    if (filters?.limit) {
      filtered = filtered.slice(0, filters.limit);
    }

    return filtered;
  }

  /**
   * Collect evidence
   */
  async collectEvidence(
    evidence: Omit<Evidence, 'id' | 'collectedAt'>
  ): Promise<Evidence> {
    const fullEvidence: Evidence = {
      ...evidence,
      id: this.generateId(),
      collectedAt: new Date(),
    };

    await this.saveEvidence(fullEvidence);

    // Record audit event
    await this.recordEvent({
      eventType: 'evidence_collection',
      actor: {
        type: evidence.collectedByType,
        id: evidence.collectedBy,
      },
      resource: {
        type: 'evidence',
        id: fullEvidence.id,
        name: fullEvidence.title,
      },
      action: 'collect_evidence',
      outcome: 'success',
      details: {
        evidenceType: evidence.type,
        reference: evidence.reference,
      },
    });

    return fullEvidence;
  }

  /**
   * Get evidence
   */
  async getEvidence(filters?: {
    type?: Evidence['type'][];
    collectedBy?: string;
    complianceFrameworks?: string[];
    relatedControls?: string[];
    tags?: string[];
    limit?: number;
  }): Promise<Evidence[]> {
    const evidence = await this.loadEvidence();

    let filtered = evidence;

    if (filters?.type) {
      filtered = filtered.filter(e => filters.type!.includes(e.type));
    }
    if (filters?.collectedBy) {
      filtered = filtered.filter(e => e.collectedBy === filters.collectedBy);
    }
    if (filters?.complianceFrameworks) {
      filtered = filtered.filter(e =>
        e.complianceFrameworks?.some(f => filters.complianceFrameworks!.includes(f))
      );
    }
    if (filters?.relatedControls) {
      filtered = filtered.filter(e =>
        e.relatedControls?.some(c => filters.relatedControls!.includes(c))
      );
    }
    if (filters?.tags) {
      filtered = filtered.filter(e =>
        e.tags?.some(t => filters.tags!.includes(t))
      );
    }

    // Filter expired evidence
    filtered = filtered.filter(e => {
      if (e.expirationDate) {
        return e.expirationDate > new Date();
      }
      return true;
    });

    // Sort by collectedAt descending
    filtered.sort((a, b) => b.collectedAt.getTime() - a.collectedAt.getTime());

    if (filters?.limit) {
      filtered = filtered.slice(0, filters.limit);
    }

    return filtered;
  }

  /**
   * Generate compliance report
   */
  async generateComplianceReport(
    framework: string,
    period: { start: Date; end: Date },
    controls: Array<{
      controlId: string;
      controlTitle: string;
      status: 'compliant' | 'non-compliant' | 'not-assessed' | 'partial';
      evidence?: string[];
      findings?: string[];
      notes?: string;
    }>,
    generatedBy: string
  ): Promise<ComplianceReport> {
    // Collect evidence for controls
    const evidenceIds = new Set<string>();
    controls.forEach(control => {
      control.evidence?.forEach(id => evidenceIds.add(id));
    });

    const evidence = await Promise.all(
      Array.from(evidenceIds).map(id => this.getEvidenceById(id))
    );
    const validEvidence = evidence.filter(e => e !== null) as Evidence[];

    // Calculate summary
    const totalControls = controls.length;
    const compliantControls = controls.filter(c => c.status === 'compliant').length;
    const nonCompliantControls = controls.filter(c => c.status === 'non-compliant').length;
    const notAssessedControls = controls.filter(c => c.status === 'not-assessed').length;
    const complianceScore = totalControls > 0
      ? Math.round((compliantControls / totalControls) * 100)
      : 0;

    // Generate recommendations
    const recommendations = controls
      .filter(c => c.status === 'non-compliant' || c.status === 'partial')
      .map(c => ({
        priority: c.status === 'non-compliant' ? 'high' as const : 'medium' as const,
        controlId: c.controlId,
        description: `Remediate ${c.controlTitle}`,
        remediationSteps: [
          `Review control ${c.controlId}: ${c.controlTitle}`,
          'Collect required evidence',
          'Implement remediation steps',
          'Re-assess compliance status',
        ],
      }));

    const report: ComplianceReport = {
      id: this.generateId(),
      title: `${framework} Compliance Report`,
      framework,
      generatedAt: new Date(),
      generatedBy,
      period,
      summary: {
        totalControls,
        compliantControls,
        nonCompliantControls,
        notAssessedControls,
        complianceScore,
      },
      controls: controls.map(c => ({
        controlId: c.controlId,
        controlTitle: c.controlTitle,
        status: c.status,
        evidence: c.evidence || [],
        findings: c.findings || [],
        notes: c.notes,
      })),
      evidence: validEvidence,
      recommendations,
    };

    await this.saveComplianceReport(report);

    // Record audit event
    await this.recordEvent({
      eventType: 'compliance_check',
      actor: {
        type: 'user',
        id: generatedBy,
      },
      resource: {
        type: 'compliance_report',
        id: report.id,
        name: report.title,
      },
      action: 'generate_compliance_report',
      outcome: 'success',
      details: {
        framework,
        complianceScore,
        totalControls,
      },
    });

    return report;
  }

  /**
   * Create attestation
   */
  async createAttestation(
    attestation: Omit<Attestation, 'id' | 'attestedAt' | 'status'>
  ): Promise<Attestation> {
    const fullAttestation: Attestation = {
      ...attestation,
      id: this.generateId(),
      attestedAt: new Date(),
      status: 'pending',
    };

    await this.saveAttestation(fullAttestation);

    // Record audit event
    await this.recordEvent({
      eventType: 'attestation',
      actor: {
        type: 'user',
        id: attestation.attestedBy.id,
        name: attestation.attestedBy.name,
      },
      resource: {
        type: 'attestation',
        id: fullAttestation.id,
        name: fullAttestation.title,
      },
      action: 'create_attestation',
      outcome: 'success',
      details: {
        framework: attestation.framework,
        controls: attestation.controls,
      },
    });

    return fullAttestation;
  }

  /**
   * Approve/reject attestation
   */
  async reviewAttestation(
    attestationId: string,
    approver: {
      id: string;
      name: string;
      role: string;
    },
    decision: 'approved' | 'rejected',
    notes?: string
  ): Promise<Attestation> {
    const attestation = await this.getAttestationById(attestationId);
    if (!attestation) {
      throw new Error(`Attestation ${attestationId} not found`);
    }

    attestation.status = decision;
    attestation.approver = {
      ...approver,
      approvedAt: new Date(),
      notes,
    };

    await this.saveAttestation(attestation);

    // Record audit event
    await this.recordEvent({
      eventType: 'attestation',
      actor: {
        type: 'user',
        id: approver.id,
        name: approver.name,
      },
      resource: {
        type: 'attestation',
        id: attestation.id,
        name: attestation.title,
      },
      action: `review_attestation_${decision}`,
      outcome: decision === 'approved' ? 'success' : 'failure',
      details: {
        decision,
        notes,
      },
    });

    return attestation;
  }

  /**
   * Create attestation workflow
   */
  async createAttestationWorkflow(
    workflow: Omit<AttestationWorkflow, 'id' | 'createdAt' | 'updatedAt' | 'status' | 'currentStep'>
  ): Promise<AttestationWorkflow> {
    const fullWorkflow: AttestationWorkflow = {
      ...workflow,
      id: this.generateId(),
      createdAt: new Date(),
      updatedAt: new Date(),
      status: 'draft',
      currentStep: 1,
    };

    await this.saveAttestationWorkflow(fullWorkflow);
    return fullWorkflow;
  }

  /**
   * Progress attestation workflow
   */
  async progressWorkflow(
    workflowId: string,
    completedBy: string,
    stepNumber?: number
  ): Promise<AttestationWorkflow> {
    const workflow = await this.getAttestationWorkflowById(workflowId);
    if (!workflow) {
      throw new Error(`Workflow ${workflowId} not found`);
    }

    const targetStep = stepNumber || workflow.currentStep;
    const step = workflow.steps.find(s => s.stepNumber === targetStep);
    if (!step) {
      throw new Error(`Step ${targetStep} not found in workflow`);
    }

    step.completed = true;
    step.completedBy = completedBy;
    step.completedAt = new Date();

    // Move to next step
    const nextStep = workflow.steps.find(s => s.stepNumber === targetStep + 1);
    if (nextStep) {
      workflow.currentStep = targetStep + 1;
      workflow.status = 'in-progress';
    } else {
      // All steps completed
      if (workflow.steps.some(s => s.requiredApproval)) {
        workflow.status = 'pending-approval';
      } else {
        workflow.status = 'approved';
      }
    }

    workflow.updatedAt = new Date();
    await this.saveAttestationWorkflow(workflow);

    return workflow;
  }

  // Private helper methods

  private async saveAuditEvent(event: AuditEvent): Promise<void> {
    await fs.mkdir(this.auditLogDir, { recursive: true });
    const filePath = path.join(this.auditLogDir, `${event.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(event, null, 2));
  }

  private async loadAuditEvents(): Promise<AuditEvent[]> {
    try {
      const files = await fs.readdir(this.auditLogDir);
      const events: AuditEvent[] = [];

      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(this.auditLogDir, file), 'utf-8');
          const event = JSON.parse(content);
          event.timestamp = new Date(event.timestamp);
          events.push(event);
        }
      }

      return events;
    } catch {
      return [];
    }
  }

  private async saveEvidence(evidence: Evidence): Promise<void> {
    await fs.mkdir(this.evidenceDir, { recursive: true });
    const filePath = path.join(this.evidenceDir, `${evidence.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(evidence, null, 2));
  }

  private async loadEvidence(): Promise<Evidence[]> {
    try {
      const files = await fs.readdir(this.evidenceDir);
      const evidence: Evidence[] = [];

      for (const file of files) {
        if (file.endsWith('.json')) {
          const content = await fs.readFile(path.join(this.evidenceDir, file), 'utf-8');
          const ev = JSON.parse(content);
          ev.collectedAt = new Date(ev.collectedAt);
          if (ev.expirationDate) {
            ev.expirationDate = new Date(ev.expirationDate);
          }
          evidence.push(ev);
        }
      }

      return evidence;
    } catch {
      return [];
    }
  }

  private async getEvidenceById(id: string): Promise<Evidence | null> {
    try {
      const filePath = path.join(this.evidenceDir, `${id}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      const evidence = JSON.parse(content);
      evidence.collectedAt = new Date(evidence.collectedAt);
      if (evidence.expirationDate) {
        evidence.expirationDate = new Date(evidence.expirationDate);
      }
      return evidence;
    } catch {
      return null;
    }
  }

  private async saveComplianceReport(report: ComplianceReport): Promise<void> {
    await fs.mkdir(this.reportsDir, { recursive: true });
    const filePath = path.join(this.reportsDir, `${report.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(report, null, 2));
  }

  private async saveAttestation(attestation: Attestation): Promise<void> {
    await fs.mkdir(this.attestationsDir, { recursive: true });
    const filePath = path.join(this.attestationsDir, `${attestation.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(attestation, null, 2));
  }

  private async getAttestationById(id: string): Promise<Attestation | null> {
    try {
      const filePath = path.join(this.attestationsDir, `${id}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      const attestation = JSON.parse(content);
      attestation.attestedAt = new Date(attestation.attestedAt);
      if (attestation.approver?.approvedAt) {
        attestation.approver.approvedAt = new Date(attestation.approver.approvedAt);
      }
      if (attestation.expirationDate) {
        attestation.expirationDate = new Date(attestation.expirationDate);
      }
      return attestation;
    } catch {
      return null;
    }
  }

  private async saveAttestationWorkflow(workflow: AttestationWorkflow): Promise<void> {
    await fs.mkdir(this.attestationsDir, { recursive: true });
    const filePath = path.join(this.attestationsDir, `workflow-${workflow.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(workflow, null, 2));
  }

  private async getAttestationWorkflowById(id: string): Promise<AttestationWorkflow | null> {
    try {
      const filePath = path.join(this.attestationsDir, `workflow-${id}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      const workflow = JSON.parse(content);
      workflow.createdAt = new Date(workflow.createdAt);
      workflow.updatedAt = new Date(workflow.updatedAt);
      workflow.steps.forEach((step: any) => {
        if (step.completedAt) {
          step.completedAt = new Date(step.completedAt);
        }
      });
      return workflow;
    } catch {
      return null;
    }
  }

  private generateId(): string {
    return `evt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

