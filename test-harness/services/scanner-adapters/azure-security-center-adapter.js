"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AzureSecurityCenterAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class AzureSecurityCenterAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'azure-security-center',
            source: 'cspm',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const azureFinding = finding;
        return !!(azureFinding.id &&
            azureFinding.properties &&
            azureFinding.properties.displayName &&
            azureFinding.properties.severity);
    }
    normalize(finding, metadata) {
        const azureFinding = finding;
        const severity = this.extractSeverity(azureFinding);
        const resourceId = azureFinding.properties.resourceIdentifiers?.azureResourceId ||
            azureFinding.id;
        return {
            id: this.generateFindingId(azureFinding.id),
            event: {
                kind: 'event',
                category: 'security',
                type: azureFinding.properties.isIncident ? 'alert' : 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'cspm',
            scannerId: 'azure-security-center',
            scannerFindingId: azureFinding.id,
            title: azureFinding.properties.displayName,
            description: azureFinding.properties.description,
            severity,
            confidence: azureFinding.properties.confidenceScore
                ? (azureFinding.properties.confidenceScore >= 0.8 ? 'confirmed' :
                    azureFinding.properties.confidenceScore >= 0.5 ? 'firm' : 'tentative')
                : 'firm',
            asset: {
                type: 'infrastructure',
                applicationId: metadata?.applicationId,
                component: resourceId,
                location: {
                    resource: resourceId,
                    region: this.extractRegion(resourceId),
                },
            },
            host: {
                name: azureFinding.properties.compromisedEntity || resourceId,
                id: resourceId,
            },
            compliance: this.extractCompliance(azureFinding),
            vulnerability: {
                severity,
                scanner: {
                    vendor: 'Microsoft',
                    name: 'Azure Security Center',
                },
            },
            remediation: {
                description: azureFinding.properties.remediationDescription ||
                    azureFinding.properties.description,
                steps: azureFinding.properties.remediationSteps ||
                    this.extractRemediationSteps(azureFinding),
                references: azureFinding.properties.extendedLinks?.map(link => link.url) || [],
                automated: false,
            },
            status: this.mapStatus(azureFinding.properties.state),
            createdAt: new Date(azureFinding.properties.timeGeneratedUtc),
            updatedAt: new Date(azureFinding.properties.timeGeneratedUtc),
            riskScore: this.calculateRiskScore(severity, azureFinding.properties.canBeInvestigated ? 'potentially-exploitable' : 'not-exploitable'),
            relatedFindings: azureFinding.properties.sourceSystemIds?.map(id => this.generateFindingId(id)),
            raw: azureFinding,
        };
    }
    extractSeverity(finding) {
        const azureFinding = finding;
        const mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Informational': 'info',
        };
        return mapping[azureFinding.properties.severity] || 'medium';
    }
    extractRegion(resourceId) {
        const match = resourceId.match(/\/locations\/([^\/]+)/);
        return match ? match[1] : undefined;
    }
    extractCompliance(azureFinding) {
        const frameworks = [];
        const controls = [];
        if (azureFinding.properties.extendedProperties) {
            const compliance = azureFinding.properties.extendedProperties['compliance'];
            if (compliance) {
                if (typeof compliance === 'string') {
                    if (compliance.includes('CIS'))
                        frameworks.push('CIS-Azure');
                    if (compliance.includes('PCI'))
                        frameworks.push('PCI-DSS');
                    if (compliance.includes('SOC'))
                        frameworks.push('SOC2');
                    if (compliance.includes('HIPAA'))
                        frameworks.push('HIPAA');
                    if (compliance.includes('ISO'))
                        frameworks.push('ISO-27001');
                }
            }
            const controlId = azureFinding.properties.extendedProperties['controlId'];
            if (controlId) {
                controls.push(controlId);
            }
        }
        if (frameworks.length === 0) {
            frameworks.push('Azure-Security-Center');
        }
        return {
            frameworks,
            controls,
            requirements: controls,
            rule: {
                id: azureFinding.properties.alertType || azureFinding.id,
                name: azureFinding.properties.displayName,
                category: azureFinding.properties.vendorName || 'Azure',
                description: azureFinding.properties.description,
            },
        };
    }
    extractRemediationSteps(azureFinding) {
        const steps = [];
        if (azureFinding.properties.remediationDescription) {
            steps.push(azureFinding.properties.remediationDescription);
        }
        if (azureFinding.properties.resourceIdentifiers?.azureResourceId) {
            steps.push(`Review Azure resource: ${azureFinding.properties.resourceIdentifiers.azureResourceId}`);
        }
        if (azureFinding.properties.extendedLinks) {
            azureFinding.properties.extendedLinks.forEach(link => {
                steps.push(`${link.label}: ${link.url}`);
            });
        }
        return steps.length > 0 ? steps : ['Review and fix the security configuration in Azure Security Center'];
    }
    mapStatus(state) {
        if (!state)
            return 'open';
        const mapping = {
            'Active': 'open',
            'Resolved': 'resolved',
            'Dismissed': 'risk-accepted',
        };
        return mapping[state] || 'open';
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
exports.AzureSecurityCenterAdapter = AzureSecurityCenterAdapter;
//# sourceMappingURL=azure-security-center-adapter.js.map