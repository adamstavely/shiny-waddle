"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AWSSecurityHubAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class AWSSecurityHubAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'aws-security-hub',
            source: 'cspm',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const hubFinding = finding;
        return !!(hubFinding.Id &&
            hubFinding.Title &&
            hubFinding.Severity &&
            hubFinding.Resources &&
            hubFinding.Resources.length > 0);
    }
    normalize(finding, metadata) {
        const hubFinding = finding;
        const severity = this.extractSeverity(hubFinding);
        const resource = hubFinding.Resources[0];
        return {
            id: this.generateFindingId(hubFinding.Id),
            event: {
                kind: 'event',
                category: hubFinding.Compliance ? 'compliance' : 'security',
                type: hubFinding.Compliance ? 'compliance-violation' : 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'cspm',
            scannerId: 'aws-security-hub',
            scannerFindingId: hubFinding.Id,
            title: hubFinding.Title,
            description: hubFinding.Description,
            severity,
            confidence: 'confirmed',
            asset: {
                type: 'infrastructure',
                applicationId: metadata?.applicationId,
                component: resource.Id,
                location: {
                    resource: resource.Id,
                    region: hubFinding.Region || resource.Region,
                },
            },
            host: {
                name: resource.Id,
                id: resource.Id,
            },
            compliance: hubFinding.Compliance ? {
                frameworks: this.extractFrameworks(hubFinding),
                controls: hubFinding.Compliance.RelatedRequirements || [],
                requirements: hubFinding.Compliance.RelatedRequirements || [],
                rule: {
                    id: hubFinding.GeneratorId,
                    name: hubFinding.Title,
                    category: resource.Type,
                    description: hubFinding.Description,
                },
            } : undefined,
            vulnerability: {
                severity,
                scanner: {
                    vendor: 'AWS',
                    name: 'Security Hub',
                },
            },
            remediation: {
                description: hubFinding.Remediation?.Recommendation?.Text || 'Review and fix the security issue',
                steps: this.extractRemediationSteps(hubFinding),
                references: hubFinding.Remediation?.Recommendation?.Url ? [hubFinding.Remediation.Recommendation.Url] : [],
                automated: false,
            },
            status: this.mapStatus(hubFinding.Workflow?.Status, hubFinding.RecordState),
            createdAt: new Date(hubFinding.CreatedAt),
            updatedAt: new Date(hubFinding.UpdatedAt),
            riskScore: this.calculateRiskScore(severity),
            relatedFindings: hubFinding.RelatedFindings?.map(f => this.generateFindingId(f.Id)),
            raw: hubFinding,
        };
    }
    extractSeverity(finding) {
        const hubFinding = finding;
        const mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFORMATIONAL': 'info',
        };
        return mapping[hubFinding.Severity.Label] || 'medium';
    }
    extractFrameworks(hubFinding) {
        const frameworks = [];
        if (hubFinding.ProductFields) {
            if (hubFinding.ProductFields['aws/securityhub/CompanyName']) {
                frameworks.push('AWS-Security-Hub');
            }
            if (hubFinding.ProductFields['aws/securityhub/Compliance']) {
                const compliance = hubFinding.ProductFields['aws/securityhub/Compliance'];
                if (compliance.includes('CIS'))
                    frameworks.push('CIS-AWS');
                if (compliance.includes('PCI'))
                    frameworks.push('PCI-DSS');
                if (compliance.includes('SOC'))
                    frameworks.push('SOC2');
            }
        }
        if (hubFinding.Compliance?.RelatedRequirements) {
            for (const req of hubFinding.Compliance.RelatedRequirements) {
                if (req.includes('CIS'))
                    frameworks.push('CIS-AWS');
                if (req.includes('PCI'))
                    frameworks.push('PCI-DSS');
                if (req.includes('SOC'))
                    frameworks.push('SOC2');
                if (req.includes('HIPAA'))
                    frameworks.push('HIPAA');
            }
        }
        return frameworks.length > 0 ? frameworks : ['AWS-Security-Hub'];
    }
    extractRemediationSteps(hubFinding) {
        const steps = [];
        if (hubFinding.Remediation?.Recommendation?.Text) {
            steps.push(hubFinding.Remediation.Recommendation.Text);
        }
        if (hubFinding.Resources[0]?.Type) {
            steps.push(`Review ${hubFinding.Resources[0].Type} resource: ${hubFinding.Resources[0].Id}`);
        }
        return steps.length > 0 ? steps : ['Review and fix the security configuration'];
    }
    mapStatus(workflowStatus, recordState) {
        if (recordState === 'ARCHIVED') {
            return 'resolved';
        }
        if (workflowStatus) {
            const mapping = {
                'NEW': 'open',
                'NOTIFIED': 'in-progress',
                'RESOLVED': 'resolved',
                'SUPPRESSED': 'risk-accepted',
            };
            return mapping[workflowStatus] || 'open';
        }
        return 'open';
    }
    mapSeverityToECS(severity) {
        const mapping = {
            'critical': 1000,
            'high': 750,
            'medium': 500,
            'low': 250,
            'info': 100,
        };
        return mapping[severity.toLowerCase()] || 500;
    }
}
exports.AWSSecurityHubAdapter = AWSSecurityHubAdapter;
//# sourceMappingURL=aws-security-hub-adapter.js.map