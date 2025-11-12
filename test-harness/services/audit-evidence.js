"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuditEvidenceService = void 0;
const fs = require("fs/promises");
const path = require("path");
class AuditEvidenceService {
    constructor(baseDir = './data', auditLogDir, evidenceDir, reportsDir, attestationsDir) {
        this.auditLogDir = auditLogDir || path.join(baseDir, 'audit-logs');
        this.evidenceDir = evidenceDir || path.join(baseDir, 'evidence');
        this.reportsDir = reportsDir || path.join(baseDir, 'compliance-reports');
        this.attestationsDir = attestationsDir || path.join(baseDir, 'attestations');
    }
    async recordEvent(event) {
        const auditEvent = {
            ...event,
            id: this.generateId(),
            timestamp: new Date(),
        };
        await this.saveAuditEvent(auditEvent);
        return auditEvent;
    }
    async getAuditTrail(filters) {
        const events = await this.loadAuditEvents();
        let filtered = events;
        if (filters?.eventType) {
            filtered = filtered.filter(e => filters.eventType.includes(e.eventType));
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
            filtered = filtered.filter(e => e.timestamp >= filters.startDate);
        }
        if (filters?.endDate) {
            filtered = filtered.filter(e => e.timestamp <= filters.endDate);
        }
        filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        if (filters?.limit) {
            filtered = filtered.slice(0, filters.limit);
        }
        return filtered;
    }
    async collectEvidence(evidence) {
        const fullEvidence = {
            ...evidence,
            id: this.generateId(),
            collectedAt: new Date(),
        };
        await this.saveEvidence(fullEvidence);
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
    async getEvidence(filters) {
        const evidence = await this.loadEvidence();
        let filtered = evidence;
        if (filters?.type) {
            filtered = filtered.filter(e => filters.type.includes(e.type));
        }
        if (filters?.collectedBy) {
            filtered = filtered.filter(e => e.collectedBy === filters.collectedBy);
        }
        if (filters?.complianceFrameworks) {
            filtered = filtered.filter(e => e.complianceFrameworks?.some(f => filters.complianceFrameworks.includes(f)));
        }
        if (filters?.relatedControls) {
            filtered = filtered.filter(e => e.relatedControls?.some(c => filters.relatedControls.includes(c)));
        }
        if (filters?.tags) {
            filtered = filtered.filter(e => e.tags?.some(t => filters.tags.includes(t)));
        }
        filtered = filtered.filter(e => {
            if (e.expirationDate) {
                return e.expirationDate > new Date();
            }
            return true;
        });
        filtered.sort((a, b) => b.collectedAt.getTime() - a.collectedAt.getTime());
        if (filters?.limit) {
            filtered = filtered.slice(0, filters.limit);
        }
        return filtered;
    }
    async generateComplianceReport(framework, period, controls, generatedBy) {
        const evidenceIds = new Set();
        controls.forEach(control => {
            control.evidence?.forEach(id => evidenceIds.add(id));
        });
        const evidence = await Promise.all(Array.from(evidenceIds).map(id => this.getEvidenceById(id)));
        const validEvidence = evidence.filter(e => e !== null);
        const totalControls = controls.length;
        const compliantControls = controls.filter(c => c.status === 'compliant').length;
        const nonCompliantControls = controls.filter(c => c.status === 'non-compliant').length;
        const notAssessedControls = controls.filter(c => c.status === 'not-assessed').length;
        const complianceScore = totalControls > 0
            ? Math.round((compliantControls / totalControls) * 100)
            : 0;
        const recommendations = controls
            .filter(c => c.status === 'non-compliant' || c.status === 'partial')
            .map(c => ({
            priority: c.status === 'non-compliant' ? 'high' : 'medium',
            controlId: c.controlId,
            description: `Remediate ${c.controlTitle}`,
            remediationSteps: [
                `Review control ${c.controlId}: ${c.controlTitle}`,
                'Collect required evidence',
                'Implement remediation steps',
                'Re-assess compliance status',
            ],
        }));
        const report = {
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
    async createAttestation(attestation) {
        const fullAttestation = {
            ...attestation,
            id: this.generateId(),
            attestedAt: new Date(),
            status: 'pending',
        };
        await this.saveAttestation(fullAttestation);
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
    async reviewAttestation(attestationId, approver, decision, notes) {
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
    async createAttestationWorkflow(workflow) {
        const fullWorkflow = {
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
    async progressWorkflow(workflowId, completedBy, stepNumber) {
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
        const nextStep = workflow.steps.find(s => s.stepNumber === targetStep + 1);
        if (nextStep) {
            workflow.currentStep = targetStep + 1;
            workflow.status = 'in-progress';
        }
        else {
            if (workflow.steps.some(s => s.requiredApproval)) {
                workflow.status = 'pending-approval';
            }
            else {
                workflow.status = 'approved';
            }
        }
        workflow.updatedAt = new Date();
        await this.saveAttestationWorkflow(workflow);
        return workflow;
    }
    async saveAuditEvent(event) {
        await fs.mkdir(this.auditLogDir, { recursive: true });
        const filePath = path.join(this.auditLogDir, `${event.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(event, null, 2));
    }
    async loadAuditEvents() {
        try {
            const files = await fs.readdir(this.auditLogDir);
            const events = [];
            for (const file of files) {
                if (file.endsWith('.json')) {
                    const content = await fs.readFile(path.join(this.auditLogDir, file), 'utf-8');
                    const event = JSON.parse(content);
                    event.timestamp = new Date(event.timestamp);
                    events.push(event);
                }
            }
            return events;
        }
        catch {
            return [];
        }
    }
    async saveEvidence(evidence) {
        await fs.mkdir(this.evidenceDir, { recursive: true });
        const filePath = path.join(this.evidenceDir, `${evidence.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(evidence, null, 2));
    }
    async loadEvidence() {
        try {
            const files = await fs.readdir(this.evidenceDir);
            const evidence = [];
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
        }
        catch {
            return [];
        }
    }
    async getEvidenceById(id) {
        try {
            const filePath = path.join(this.evidenceDir, `${id}.json`);
            const content = await fs.readFile(filePath, 'utf-8');
            const evidence = JSON.parse(content);
            evidence.collectedAt = new Date(evidence.collectedAt);
            if (evidence.expirationDate) {
                evidence.expirationDate = new Date(evidence.expirationDate);
            }
            return evidence;
        }
        catch {
            return null;
        }
    }
    async saveComplianceReport(report) {
        await fs.mkdir(this.reportsDir, { recursive: true });
        const filePath = path.join(this.reportsDir, `${report.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(report, null, 2));
    }
    async saveAttestation(attestation) {
        await fs.mkdir(this.attestationsDir, { recursive: true });
        const filePath = path.join(this.attestationsDir, `${attestation.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(attestation, null, 2));
    }
    async getAttestationById(id) {
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
        }
        catch {
            return null;
        }
    }
    async saveAttestationWorkflow(workflow) {
        await fs.mkdir(this.attestationsDir, { recursive: true });
        const filePath = path.join(this.attestationsDir, `workflow-${workflow.id}.json`);
        await fs.writeFile(filePath, JSON.stringify(workflow, null, 2));
    }
    async getAttestationWorkflowById(id) {
        try {
            const filePath = path.join(this.attestationsDir, `workflow-${id}.json`);
            const content = await fs.readFile(filePath, 'utf-8');
            const workflow = JSON.parse(content);
            workflow.createdAt = new Date(workflow.createdAt);
            workflow.updatedAt = new Date(workflow.updatedAt);
            workflow.steps.forEach((step) => {
                if (step.completedAt) {
                    step.completedAt = new Date(step.completedAt);
                }
            });
            return workflow;
        }
        catch {
            return null;
        }
    }
    generateId() {
        return `evt-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    }
}
exports.AuditEvidenceService = AuditEvidenceService;
//# sourceMappingURL=audit-evidence.js.map