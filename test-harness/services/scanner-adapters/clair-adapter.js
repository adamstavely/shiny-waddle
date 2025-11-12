"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ClairAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class ClairAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'clair',
            source: 'container',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const report = finding;
        if ('image' in report) {
            return !!(report.image &&
                (report.vulnerabilities ||
                    report.unpatched ||
                    report.layers ||
                    report.vulnerabilities));
        }
        if ('layers' in report && Array.isArray(report.layers)) {
            return report.layers.some(layer => layer.features?.some(feature => feature.vulnerabilities && feature.vulnerabilities.length > 0));
        }
        return false;
    }
    normalize(finding, metadata) {
        const report = finding;
        const findings = [];
        const imageParts = this.parseImageName(report.image);
        if (report.vulnerabilities && report.vulnerabilities.length > 0) {
            for (const vuln of report.vulnerabilities) {
                findings.push(this.normalizeVulnerability(vuln, imageParts, metadata));
            }
        }
        if ('unpatched' in report && report.unpatched && report.unpatched.length > 0) {
            for (const vuln of report.unpatched) {
                findings.push(this.normalizeVulnerability(vuln, imageParts, metadata));
            }
        }
        if (report.layers && report.layers.length > 0) {
            for (const layer of report.layers) {
                if (layer.features) {
                    for (const feature of layer.features) {
                        if (feature.vulnerabilities && feature.vulnerabilities.length > 0) {
                            for (const vuln of feature.vulnerabilities) {
                                findings.push(this.normalizeVulnerability(vuln, imageParts, metadata, feature));
                            }
                        }
                    }
                }
            }
        }
        return findings;
    }
    normalizeVulnerability(vuln, imageParts, metadata, feature) {
        const severity = this.extractSeverity(vuln);
        const packageName = vuln.package || feature?.name || 'unknown';
        const packageVersion = vuln.version || feature?.version || 'unknown';
        return {
            id: this.generateFindingId(`${vuln.id}-${packageName}-${imageParts.name}`),
            event: {
                kind: 'event',
                category: 'vulnerability',
                type: 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'container',
            scannerId: 'clair',
            scannerFindingId: vuln.id,
            title: vuln.name || `Vulnerability in ${packageName}`,
            description: vuln.description || vuln.name || `Security vulnerability detected in ${packageName} ${packageVersion}`,
            severity,
            confidence: 'confirmed',
            asset: {
                type: 'container',
                applicationId: metadata?.applicationId,
                component: packageName,
                location: {
                    resource: `${imageParts.name}:${imageParts.tag}`,
                    file: {
                        name: packageName,
                    },
                },
            },
            host: {
                container: {
                    id: imageParts.id,
                    name: imageParts.name,
                    image: {
                        name: imageParts.name,
                        tag: imageParts.tag,
                    },
                },
            },
            vulnerability: {
                id: vuln.id,
                cve: this.isCVE(vuln.id) ? {
                    id: vuln.id,
                    description: vuln.description,
                    score: this.extractCVSSScore(vuln),
                } : undefined,
                classification: vuln.namespace || feature?.namespace,
                severity,
                scanner: {
                    vendor: 'Quay',
                    name: 'Clair',
                    version: metadata?.clairVersion,
                },
            },
            remediation: {
                description: this.extractRemediationDescription(vuln, packageName, packageVersion),
                steps: this.extractRemediationSteps(vuln, packageName, packageVersion),
                references: this.extractReferences(vuln),
                automated: !!vuln.fixedIn,
            },
            status: 'open',
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: {
                vulnerability: vuln,
                feature,
            },
        };
    }
    extractSeverity(finding) {
        const vuln = finding;
        const mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Negligible': 'low',
            'Unknown': 'info',
        };
        return mapping[vuln.severity] || 'medium';
    }
    isCVE(id) {
        return /^CVE-\d{4}-\d{4,}$/.test(id);
    }
    extractCVSSScore(vuln) {
        const severityScores = {
            'Critical': 9.0,
            'High': 7.0,
            'Medium': 5.0,
            'Low': 3.0,
            'Negligible': 1.0,
        };
        const inferredScore = severityScores[vuln.severity];
        if (inferredScore) {
            return {
                base: inferredScore,
                version: '3.1',
            };
        }
        return undefined;
    }
    parseImageName(image) {
        let name = image;
        let tag = 'latest';
        let id;
        if (image.includes('@')) {
            const [imgName, digest] = image.split('@');
            name = imgName;
            id = digest;
            if (imgName.includes(':')) {
                const parts = imgName.split(':');
                tag = parts[parts.length - 1];
                name = parts.slice(0, -1).join(':');
            }
        }
        else if (image.includes(':')) {
            const parts = image.split(':');
            tag = parts[parts.length - 1];
            name = parts.slice(0, -1).join(':');
        }
        return {
            id,
            name: name || image,
            tag,
        };
    }
    extractRemediationDescription(vuln, packageName, packageVersion) {
        const parts = [];
        if (vuln.fixedIn) {
            parts.push(`Upgrade ${packageName} to version ${vuln.fixedIn} or later to remediate this vulnerability.`);
        }
        else {
            parts.push(`Review vulnerability ${vuln.name || vuln.id} in ${packageName} ${packageVersion}.`);
            parts.push('Check for available patches or updates from the package maintainer.');
        }
        return parts.join(' ') || 'Review and apply recommended fixes.';
    }
    extractRemediationSteps(vuln, packageName, packageVersion) {
        const steps = [];
        if (vuln.fixedIn) {
            steps.push(`Update ${packageName} from ${packageVersion} to ${vuln.fixedIn} or later`);
            steps.push('Rebuild container image with updated package');
            steps.push('Test updated container image');
            steps.push('Deploy updated image to production');
        }
        else {
            steps.push(`Review vulnerability ${vuln.name || vuln.id} in ${packageName}`);
            steps.push('Check for available patches or security updates');
            steps.push('Consider alternative packages if no fix is available');
            steps.push('Apply workarounds if documented');
        }
        return steps.length > 0 ? steps : ['Review and remediate vulnerability'];
    }
    extractReferences(vuln) {
        const refs = [];
        if (vuln.link) {
            refs.push(vuln.link);
        }
        if (this.isCVE(vuln.id)) {
            refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.id}`);
            refs.push(`https://nvd.nist.gov/vuln/detail/${vuln.id}`);
        }
        if (vuln.namespace) {
            refs.push(`https://quay.io/repository/coreos/clair?tab=tags`);
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
exports.ClairAdapter = ClairAdapter;
//# sourceMappingURL=clair-adapter.js.map