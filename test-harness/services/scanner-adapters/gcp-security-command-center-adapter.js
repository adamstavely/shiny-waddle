"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.GCPSecurityCommandCenterAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class GCPSecurityCommandCenterAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'gcp-security-command-center',
            source: 'cspm',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const gcpFinding = finding;
        return !!(gcpFinding.name &&
            gcpFinding.resourceName &&
            gcpFinding.sourceProperties);
    }
    normalize(finding, metadata) {
        const gcpFinding = finding;
        const severity = this.extractSeverity(gcpFinding);
        const props = gcpFinding.sourceProperties;
        return {
            id: this.generateFindingId(gcpFinding.name),
            event: {
                kind: 'event',
                category: 'security',
                type: props.FindingClass === 'THREAT' ? 'alert' : 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'cspm',
            scannerId: 'gcp-security-command-center',
            scannerFindingId: gcpFinding.name,
            title: props.FindingSourceDescription || props.FindingProviderName || gcpFinding.category || 'GCP Security Finding',
            description: props.FindingSourceDescription || props.FindingSourceRecommendation ||
                `Security finding in ${gcpFinding.resourceName}`,
            severity,
            confidence: props.FindingSourceConfidence
                ? (props.FindingSourceConfidence >= 0.8 ? 'confirmed' :
                    props.FindingSourceConfidence >= 0.5 ? 'firm' : 'tentative')
                : 'firm',
            asset: {
                type: 'infrastructure',
                applicationId: metadata?.applicationId,
                component: gcpFinding.resourceName,
                location: {
                    resource: gcpFinding.resourceName,
                    region: props.FindingSourceAssetRegion || props.FindingSourceAssetZone,
                },
            },
            host: {
                name: props.FindingSourceAssetName || gcpFinding.resourceName,
                id: gcpFinding.resourceName,
            },
            compliance: this.extractCompliance(gcpFinding),
            vulnerability: {
                severity,
                id: props.FindingSourceCVE,
                cve: props.FindingSourceCVE ? {
                    id: props.FindingSourceCVE,
                    score: props.FindingSourceCVSS ? { base: props.FindingSourceCVSS } : undefined
                } : undefined,
                classification: props.FindingSourceCWE,
                scanner: {
                    vendor: 'Google',
                    name: 'Security Command Center',
                },
            },
            remediation: {
                description: props.FindingSourceRemediation || props.FindingSourceRecommendation ||
                    'Review and fix the security issue in GCP',
                steps: this.extractRemediationSteps(gcpFinding),
                references: props.FindingSourceUrl ? [props.FindingSourceUrl] :
                    (gcpFinding.externalUri ? [gcpFinding.externalUri] : []),
                automated: false,
            },
            status: this.mapStatus(gcpFinding.state),
            createdAt: gcpFinding.createTime ? new Date(gcpFinding.createTime) :
                (props.FindingSourceCreateTime ? new Date(props.FindingSourceCreateTime) : new Date()),
            updatedAt: gcpFinding.updateTime ? new Date(gcpFinding.updateTime) :
                (props.FindingSourceUpdateTime ? new Date(props.FindingSourceUpdateTime) : new Date()),
            riskScore: this.calculateRiskScore(severity, props.FindingSourceExploitability, props.FindingSourceAssetType),
            raw: gcpFinding,
        };
    }
    extractSeverity(finding) {
        const gcpFinding = finding;
        const severity = gcpFinding.sourceProperties.Severity ||
            gcpFinding.sourceProperties.FindingSourceSeverity;
        if (!severity)
            return 'medium';
        const mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low',
            'INFO': 'info',
            'INFORMATIONAL': 'info',
        };
        return mapping[severity.toUpperCase()] || 'medium';
    }
    extractCompliance(gcpFinding) {
        const frameworks = [];
        const controls = [];
        const compliance = gcpFinding.sourceProperties.FindingSourceCompliance;
        if (compliance && Array.isArray(compliance)) {
            compliance.forEach((comp) => {
                if (comp.includes('CIS'))
                    frameworks.push('CIS-GCP');
                if (comp.includes('PCI'))
                    frameworks.push('PCI-DSS');
                if (comp.includes('SOC'))
                    frameworks.push('SOC2');
                if (comp.includes('HIPAA'))
                    frameworks.push('HIPAA');
                if (comp.includes('ISO'))
                    frameworks.push('ISO-27001');
                if (comp.includes('NIST'))
                    frameworks.push('NIST-800-53');
                controls.push(comp);
            });
        }
        if (frameworks.length === 0) {
            frameworks.push('GCP-Security-Command-Center');
        }
        return {
            frameworks,
            controls,
            requirements: controls,
            rule: {
                id: gcpFinding.sourceProperties.FindingProviderId || gcpFinding.name,
                name: gcpFinding.sourceProperties.FindingProviderName || gcpFinding.category,
                category: gcpFinding.sourceProperties.ScannerName || 'GCP',
                description: gcpFinding.sourceProperties.FindingSourceDescription || '',
            },
        };
    }
    extractRemediationSteps(gcpFinding) {
        const steps = [];
        const props = gcpFinding.sourceProperties;
        if (props.FindingSourceRemediation) {
            steps.push(props.FindingSourceRemediation);
        }
        if (props.FindingSourceRecommendation) {
            steps.push(props.FindingSourceRecommendation);
        }
        if (gcpFinding.resourceName) {
            steps.push(`Review GCP resource: ${gcpFinding.resourceName}`);
        }
        if (props.FindingSourceAssetProject) {
            steps.push(`Check project: ${props.FindingSourceAssetProject}`);
        }
        if (gcpFinding.externalUri) {
            steps.push(`See details: ${gcpFinding.externalUri}`);
        }
        return steps.length > 0 ? steps : ['Review and fix the security configuration in GCP Security Command Center'];
    }
    mapStatus(state) {
        if (!state)
            return 'open';
        const mapping = {
            'ACTIVE': 'open',
            'INACTIVE': 'resolved',
        };
        return mapping[state] || 'open';
    }
    mapExploitability(exploitability) {
        if (!exploitability)
            return 'potentially-exploitable';
        const lower = exploitability.toLowerCase();
        if (lower.includes('exploitable') || lower.includes('active')) {
            return 'exploitable';
        }
        if (lower.includes('potential') || lower.includes('possible')) {
            return 'potentially-exploitable';
        }
        return 'not-exploitable';
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
exports.GCPSecurityCommandCenterAdapter = GCPSecurityCommandCenterAdapter;
//# sourceMappingURL=gcp-security-command-center-adapter.js.map