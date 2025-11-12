"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SnykAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class SnykAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config, scanType = 'sca') {
        super({
            scannerId: scanType === 'container' ? 'snyk-container' : 'snyk',
            source: scanType === 'container' ? 'container' : 'sca',
            enabled: true,
            config,
        });
        this.scanType = scanType;
    }
    validate(finding) {
        const vuln = finding;
        const hasPackage = 'package' in vuln ? !!vuln.package : !!vuln.pkgName;
        return !!(vuln.id &&
            vuln.title &&
            vuln.severity &&
            hasPackage);
    }
    normalize(finding, metadata) {
        const vuln = finding;
        const severity = this.extractSeverity(vuln);
        const cveId = this.extractCVE(vuln);
        const cweId = this.extractCWE(vuln);
        const findingBase = {
            id: this.generateFindingId(vuln.id),
            event: {
                kind: 'event',
                category: 'vulnerability',
                type: 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: this.scanType === 'container' ? 'container' : 'sca',
            scannerId: this.scanType === 'container' ? 'snyk-container' : 'snyk',
            scannerFindingId: vuln.id,
            title: vuln.title,
            description: vuln.description,
            severity,
            confidence: 'confirmed',
            asset: {
                type: this.scanType === 'container' ? 'container' : 'dependency',
                applicationId: metadata?.applicationId,
                component: ('package' in vuln ? vuln.package : vuln.pkgName) || '',
            },
            vulnerability: {
                id: cveId,
                cve: cveId ? {
                    id: cveId,
                    description: vuln.description,
                    score: vuln.cvssScore ? {
                        base: vuln.cvssScore,
                        version: '3.1',
                    } : undefined,
                } : undefined,
                classification: cweId,
                severity,
                scanner: {
                    vendor: 'Snyk',
                    name: this.scanType === 'container' ? 'Snyk Container' : 'Snyk',
                    version: metadata?.snykVersion,
                },
            },
            remediation: {
                description: this.extractRemediationDescription(vuln),
                steps: this.extractRemediationSteps(vuln),
                references: this.extractReferences(vuln),
                automated: vuln.isPatchable || vuln.isUpgradable || false,
            },
            status: 'open',
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: vuln,
        };
        if (this.scanType === 'container' && 'dockerImageName' in vuln) {
            const containerVuln = vuln;
            findingBase.host = {
                container: {
                    id: containerVuln.dockerImageId,
                    name: containerVuln.dockerImageName,
                    image: {
                        name: containerVuln.dockerImageName,
                        tag: containerVuln.dockerImageTag,
                    },
                },
            };
            findingBase.asset.location = {
                ...findingBase.asset.location,
                resource: containerVuln.dockerBaseImage,
            };
        }
        if (this.scanType === 'sca') {
            const pkg = 'package' in vuln ? vuln.package : vuln.pkgName;
            const version = 'version' in vuln ? vuln.version : vuln.pkgVersion;
            findingBase.asset.location = {
                ...findingBase.asset.location,
                resource: `${pkg || ''}@${version || ''}`,
            };
        }
        return findingBase;
    }
    extractSeverity(finding) {
        const vuln = finding;
        return vuln.severity || 'medium';
    }
    extractCVE(vuln) {
        if (vuln.cves && vuln.cves.length > 0) {
            return vuln.cves[0];
        }
        if (vuln.identifiers?.CVE && vuln.identifiers.CVE.length > 0) {
            return vuln.identifiers.CVE[0];
        }
        return undefined;
    }
    extractCWE(vuln) {
        if (vuln.cwe && vuln.cwe.length > 0) {
            return vuln.cwe[0];
        }
        if (vuln.identifiers?.CWE && vuln.identifiers.CWE.length > 0) {
            return vuln.identifiers.CWE[0];
        }
        return undefined;
    }
    extractRemediationDescription(vuln) {
        const parts = [];
        if (vuln.isPatchable) {
            parts.push('A patch is available for this vulnerability.');
        }
        if (vuln.isUpgradable && 'upgradePath' in vuln && vuln.upgradePath) {
            parts.push(`Upgrade path: ${vuln.upgradePath.join(' -> ')}`);
        }
        if ('fixedIn' in vuln && vuln.fixedIn && vuln.fixedIn.length > 0) {
            parts.push(`Fixed in versions: ${vuln.fixedIn.join(', ')}`);
        }
        return parts.join(' ') || 'Review and apply recommended fixes.';
    }
    extractRemediationSteps(vuln) {
        const steps = [];
        if (vuln.isPatchable) {
            steps.push('Apply the available patch using: snyk patch');
        }
        if (vuln.isUpgradable && 'upgradePath' in vuln && vuln.upgradePath) {
            const pkg = 'package' in vuln ? vuln.package : vuln.pkgName;
            steps.push(`Upgrade ${pkg || 'package'} to version ${vuln.upgradePath[vuln.upgradePath.length - 1]}`);
        }
        if (!vuln.isPatchable && !vuln.isUpgradable) {
            steps.push('Review the vulnerability and consider alternative dependencies');
            steps.push('Monitor for future patches or updates');
        }
        return steps.length > 0 ? steps : ['Review vulnerability details and apply appropriate remediation'];
    }
    extractReferences(vuln) {
        const refs = [];
        const cveId = this.extractCVE(vuln);
        if (cveId) {
            refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`);
        }
        const cweId = this.extractCWE(vuln);
        if (cweId) {
            refs.push(`https://cwe.mitre.org/data/definitions/${cweId.replace('CWE-', '')}.html`);
        }
        if ('identifiers' in vuln && vuln.identifiers?.GHSA) {
            vuln.identifiers.GHSA.forEach(ghsa => {
                refs.push(`https://github.com/advisories/${ghsa}`);
            });
        }
        refs.push(`https://snyk.io/vuln/${vuln.id}`);
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
exports.SnykAdapter = SnykAdapter;
//# sourceMappingURL=snyk-adapter.js.map