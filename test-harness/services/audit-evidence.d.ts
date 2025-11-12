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
    reference: string;
    collectedAt: Date;
    collectedBy: string;
    collectedByType: 'user' | 'system' | 'automated';
    metadata?: Record<string, any>;
    tags?: string[];
    complianceFrameworks?: string[];
    relatedControls?: string[];
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
        evidence: string[];
        findings: string[];
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
    controls: string[];
    attestedBy: {
        id: string;
        name: string;
        role: string;
        email?: string;
    };
    attestedAt: Date;
    status: 'pending' | 'approved' | 'rejected' | 'expired';
    evidence: string[];
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
export declare class AuditEvidenceService {
    private auditLogDir;
    private evidenceDir;
    private reportsDir;
    private attestationsDir;
    constructor(baseDir?: string, auditLogDir?: string, evidenceDir?: string, reportsDir?: string, attestationsDir?: string);
    recordEvent(event: Omit<AuditEvent, 'id' | 'timestamp'>): Promise<AuditEvent>;
    getAuditTrail(filters?: {
        eventType?: AuditEvent['eventType'][];
        actorId?: string;
        resourceType?: string;
        resourceId?: string;
        startDate?: Date;
        endDate?: Date;
        limit?: number;
    }): Promise<AuditEvent[]>;
    collectEvidence(evidence: Omit<Evidence, 'id' | 'collectedAt'>): Promise<Evidence>;
    getEvidence(filters?: {
        type?: Evidence['type'][];
        collectedBy?: string;
        complianceFrameworks?: string[];
        relatedControls?: string[];
        tags?: string[];
        limit?: number;
    }): Promise<Evidence[]>;
    generateComplianceReport(framework: string, period: {
        start: Date;
        end: Date;
    }, controls: Array<{
        controlId: string;
        controlTitle: string;
        status: 'compliant' | 'non-compliant' | 'not-assessed' | 'partial';
        evidence?: string[];
        findings?: string[];
        notes?: string;
    }>, generatedBy: string): Promise<ComplianceReport>;
    createAttestation(attestation: Omit<Attestation, 'id' | 'attestedAt' | 'status'>): Promise<Attestation>;
    reviewAttestation(attestationId: string, approver: {
        id: string;
        name: string;
        role: string;
    }, decision: 'approved' | 'rejected', notes?: string): Promise<Attestation>;
    createAttestationWorkflow(workflow: Omit<AttestationWorkflow, 'id' | 'createdAt' | 'updatedAt' | 'status' | 'currentStep'>): Promise<AttestationWorkflow>;
    progressWorkflow(workflowId: string, completedBy: string, stepNumber?: number): Promise<AttestationWorkflow>;
    private saveAuditEvent;
    private loadAuditEvents;
    private saveEvidence;
    private loadEvidence;
    private getEvidenceById;
    private saveComplianceReport;
    private saveAttestation;
    private getAttestationById;
    private saveAttestationWorkflow;
    private getAttestationWorkflowById;
    private generateId;
}
