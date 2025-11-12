"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SonatypeIQAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class SonatypeIQAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'sonatype-iq',
            source: 'sca',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const iqFinding = finding;
        if ('components' in iqFinding) {
            return !!(iqFinding.application?.id ||
                iqFinding.components ||
                iqFinding.summary);
        }
        else {
            return !!(iqFinding.component &&
                (iqFinding.vulnerabilities?.length > 0 ||
                    iqFinding.policyViolations?.length > 0 ||
                    iqFinding.licenses?.length > 0));
        }
    }
    normalize(finding, metadata) {
        const iqFinding = finding;
        if ('components' in iqFinding && iqFinding.components) {
            const findings = [];
            for (const component of iqFinding.components) {
                const componentFindings = this.normalizeComponent(component, {
                    ...metadata,
                    applicationId: iqFinding.application?.id || metadata?.applicationId,
                    applicationName: iqFinding.application?.name || metadata?.applicationName,
                });
                findings.push(...componentFindings);
            }
            return findings;
        }
        return this.normalizeComponent(iqFinding, metadata);
    }
    normalizeComponent(component, metadata) {
        const findings = [];
        if (component.vulnerabilities && component.vulnerabilities.length > 0) {
            for (const vuln of component.vulnerabilities) {
                findings.push(this.normalizeVulnerability(component, vuln, metadata));
            }
        }
        if (component.policyViolations && component.policyViolations.length > 0) {
            for (const violation of component.policyViolations) {
                findings.push(this.normalizePolicyViolation(component, violation, metadata));
            }
        }
        if (component.licenses && component.licenses.length > 0) {
            for (const license of component.licenses) {
                if (license.licenseThreatGroup && license.licenseThreatGroup >= 7) {
                    findings.push(this.normalizeLicenseIssue(component, license, metadata));
                }
            }
        }
        return findings.length > 0 ? findings : [this.normalizeComponentOnly(component, metadata)];
    }
    normalizeVulnerability(component, vuln, metadata) {
        const severity = this.extractSeverity(vuln);
        const componentName = this.extractComponentName(component);
        const componentVersion = this.extractComponentVersion(component);
        return {
            id: this.generateFindingId(`${component.component?.hash || componentName}-${vuln.id}`),
            event: {
                kind: 'event',
                category: 'vulnerability',
                type: 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'sca',
            scannerId: 'sonatype-iq',
            scannerFindingId: vuln.id,
            title: vuln.title || vuln.cve || `Vulnerability in ${componentName}`,
            description: vuln.description || vuln.title || `Security vulnerability detected in ${componentName}`,
            severity,
            confidence: 'confirmed',
            asset: {
                type: 'dependency',
                applicationId: component.applicationId || metadata?.applicationId,
                component: componentName,
                location: {
                    resource: component.component?.packageUrl || `${componentName}@${componentVersion}`,
                },
            },
            vulnerability: {
                id: vuln.cve || vuln.id,
                cve: vuln.cve ? {
                    id: vuln.cve,
                    description: vuln.description,
                    score: vuln.cvssScore ? {
                        base: vuln.cvssScore,
                        version: vuln.cvssVector?.includes('CVSS:3') ? '3.1' : '2.0',
                    } : undefined,
                } : undefined,
                classification: vuln.cwe,
                severity,
                scanner: {
                    vendor: 'Sonatype',
                    name: 'Sonatype IQ',
                    version: metadata?.iqVersion,
                },
            },
            remediation: {
                description: this.extractRemediationDescription(vuln, component),
                steps: this.extractRemediationSteps(vuln, component),
                references: this.extractReferences(vuln),
                automated: !!vuln.remediation?.version,
            },
            status: 'open',
            createdAt: vuln.publishedDate ? new Date(vuln.publishedDate) : new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: {
                component,
                vulnerability: vuln,
            },
        };
    }
    normalizePolicyViolation(component, violation, metadata) {
        const severity = this.mapThreatLevelToSeverity(violation.threatLevel);
        const componentName = this.extractComponentName(component);
        return {
            id: this.generateFindingId(`${component.component?.hash || componentName}-${violation.policyViolationId}`),
            event: {
                kind: 'event',
                category: 'security',
                type: 'policy-violation',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'sca',
            scannerId: 'sonatype-iq',
            scannerFindingId: violation.policyViolationId,
            title: `${violation.policyName}: ${violation.constraintName}`,
            description: `Policy violation: ${violation.constraintName} in component ${componentName}. Policy: ${violation.policyName}`,
            severity,
            confidence: 'confirmed',
            asset: {
                type: 'dependency',
                applicationId: component.applicationId || metadata?.applicationId,
                component: componentName,
                location: {
                    resource: component.component?.packageUrl || componentName,
                },
            },
            vulnerability: {
                id: violation.constraintId,
                classification: violation.constraintName,
                severity,
                scanner: {
                    vendor: 'Sonatype',
                    name: 'Sonatype IQ',
                    version: metadata?.iqVersion,
                },
            },
            remediation: {
                description: `Component ${componentName} violates policy ${violation.policyName}. Review and remediate according to policy requirements.`,
                steps: [
                    `Review policy violation: ${violation.constraintName}`,
                    `Assess component ${componentName}`,
                    `Remediate or request policy exception if appropriate`,
                ],
                references: [],
                automated: false,
            },
            status: 'open',
            createdAt: violation.reportTime ? new Date(violation.reportTime) : new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: {
                component,
                policyViolation: violation,
            },
        };
    }
    normalizeLicenseIssue(component, license, metadata) {
        const severity = this.mapLicenseThreatToSeverity(license.licenseThreatGroup || 0);
        const componentName = this.extractComponentName(component);
        return {
            id: this.generateFindingId(`${component.component?.hash || componentName}-license-${license.licenseId}`),
            event: {
                kind: 'event',
                category: 'security',
                type: 'license-violation',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'sca',
            scannerId: 'sonatype-iq',
            scannerFindingId: `license-${license.licenseId}`,
            title: `License Issue: ${license.licenseName}`,
            description: `Component ${componentName} uses license ${license.licenseName} with high threat level (${license.licenseThreatGroup}). Review license compliance requirements.`,
            severity,
            confidence: 'confirmed',
            asset: {
                type: 'dependency',
                applicationId: component.applicationId || metadata?.applicationId,
                component: componentName,
                location: {
                    resource: component.component?.packageUrl || componentName,
                },
            },
            vulnerability: {
                id: license.licenseId,
                classification: license.licenseName,
                severity,
                scanner: {
                    vendor: 'Sonatype',
                    name: 'Sonatype IQ',
                    version: metadata?.iqVersion,
                },
            },
            remediation: {
                description: `Review license ${license.licenseName} for component ${componentName}. Ensure compliance with organizational policies.`,
                steps: [
                    `Review license terms: ${license.licenseName}`,
                    `Assess compliance with organizational policies`,
                    `Consider alternative component if license is not acceptable`,
                ],
                references: [],
                automated: false,
            },
            status: 'open',
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: {
                component,
                license,
            },
        };
    }
    normalizeComponentOnly(component, metadata) {
        const componentName = this.extractComponentName(component);
        return {
            id: this.generateFindingId(`${component.component?.hash || componentName}-component`),
            event: {
                kind: 'event',
                category: 'security',
                type: 'component-detected',
                action: 'detected',
                severity: 100,
            },
            source: 'sca',
            scannerId: 'sonatype-iq',
            scannerFindingId: component.component?.hash || componentName,
            title: `Component: ${componentName}`,
            description: `Component ${componentName} detected in scan`,
            severity: 'info',
            confidence: 'confirmed',
            asset: {
                type: 'dependency',
                applicationId: component.applicationId || metadata?.applicationId,
                component: componentName,
                location: {
                    resource: component.component?.packageUrl || componentName,
                },
            },
            status: 'open',
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: 10,
            raw: component,
        };
    }
    extractSeverity(finding) {
        const vuln = finding;
        if (vuln.severity) {
            const mapping = {
                'CRITICAL': 'critical',
                'SEVERE': 'high',
                'MODERATE': 'medium',
                'LOW': 'low',
                'INFO': 'info',
            };
            return mapping[vuln.severity] || 'medium';
        }
        if (vuln.cvssScore !== undefined) {
            if (vuln.cvssScore >= 9.0)
                return 'critical';
            if (vuln.cvssScore >= 7.0)
                return 'high';
            if (vuln.cvssScore >= 4.0)
                return 'medium';
            if (vuln.cvssScore > 0)
                return 'low';
            return 'info';
        }
        return 'medium';
    }
    extractComponentName(component) {
        if (component.component?.displayName) {
            return component.component.displayName;
        }
        if (component.component?.componentIdentifier?.coordinates) {
            const coords = component.component.componentIdentifier.coordinates;
            return `${coords.groupId || ''}:${coords.artifactId || ''}`.replace(/^:/, '');
        }
        if (component.component?.packageUrl) {
            return component.component.packageUrl;
        }
        return 'unknown-component';
    }
    extractComponentVersion(component) {
        if (component.component?.componentIdentifier?.coordinates?.version) {
            return component.component.componentIdentifier.coordinates.version;
        }
        return 'unknown';
    }
    mapThreatLevelToSeverity(threatLevel) {
        if (threatLevel >= 9)
            return 'critical';
        if (threatLevel >= 7)
            return 'high';
        if (threatLevel >= 5)
            return 'medium';
        if (threatLevel >= 3)
            return 'low';
        return 'info';
    }
    mapLicenseThreatToSeverity(threatGroup) {
        if (threatGroup >= 9)
            return 'critical';
        if (threatGroup >= 7)
            return 'high';
        if (threatGroup >= 5)
            return 'medium';
        if (threatGroup >= 3)
            return 'low';
        return 'info';
    }
    extractRemediationDescription(vuln, component) {
        const parts = [];
        if (vuln.remediation?.version) {
            parts.push(`Upgrade to version ${vuln.remediation.version} to remediate this vulnerability.`);
        }
        if (vuln.remediation?.description) {
            parts.push(vuln.remediation.description);
        }
        return parts.join(' ') || 'Review vulnerability details and apply recommended remediation.';
    }
    extractRemediationSteps(vuln, component) {
        const steps = [];
        const componentName = this.extractComponentName(component);
        if (vuln.remediation?.version) {
            steps.push(`Upgrade ${componentName} to version ${vuln.remediation.version}`);
        }
        else {
            steps.push(`Review vulnerability ${vuln.cve || vuln.id} in component ${componentName}`);
            steps.push('Check for available patches or updates');
            steps.push('Consider alternative component if no fix is available');
        }
        return steps.length > 0 ? steps : ['Review and remediate vulnerability'];
    }
    extractReferences(vuln) {
        const refs = [];
        if (vuln.cve) {
            refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}`);
            refs.push(`https://nvd.nist.gov/vuln/detail/${vuln.cve}`);
        }
        if (vuln.cwe) {
            const cweNum = vuln.cwe.replace('CWE-', '');
            refs.push(`https://cwe.mitre.org/data/definitions/${cweNum}.html`);
        }
        if (vuln.reference) {
            refs.push(vuln.reference);
        }
        if (vuln.source) {
            refs.push(`https://ossindex.sonatype.org/vulnerability/${vuln.id}`);
        }
        return refs;
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
exports.SonatypeIQAdapter = SonatypeIQAdapter;
//# sourceMappingURL=sonatype-iq-adapter.js.map