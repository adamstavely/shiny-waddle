"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OWASPZAPAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class OWASPZAPAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'owasp-zap',
            source: 'dast',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const alert = finding;
        return !!(alert.id &&
            alert.name &&
            alert.risk &&
            alert.url);
    }
    normalize(finding, metadata) {
        const alert = finding;
        const severity = this.extractSeverity(alert);
        const urlParts = this.parseURL(alert.url);
        return {
            id: this.generateFindingId(`${alert.pluginId}-${alert.id}`),
            event: {
                kind: 'event',
                category: 'vulnerability',
                type: 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'dast',
            scannerId: 'owasp-zap',
            scannerFindingId: `${alert.pluginId}-${alert.id}`,
            title: alert.name,
            description: alert.description,
            severity,
            confidence: this.mapConfidence(alert.confidence),
            asset: {
                type: 'api',
                applicationId: metadata?.applicationId,
                component: alert.url,
                location: {
                    url: {
                        original: alert.url,
                        scheme: urlParts.scheme,
                        domain: urlParts.domain,
                        port: urlParts.port,
                        path: urlParts.path,
                        query: urlParts.query,
                        fragment: urlParts.fragment,
                    },
                },
            },
            vulnerability: {
                id: alert.cweid ? `CWE-${alert.cweid}` : undefined,
                classification: alert.cweid ? `CWE-${alert.cweid}` : undefined,
                severity,
                scanner: {
                    vendor: 'OWASP',
                    name: 'ZAP',
                    version: metadata?.zapVersion,
                },
            },
            threat: alert.cweid ? {
                framework: 'CWE',
                technique: {
                    id: `CWE-${alert.cweid}`,
                    reference: `https://cwe.mitre.org/data/definitions/${alert.cweid}.html`,
                },
            } : undefined,
            remediation: {
                description: alert.solution,
                steps: this.extractRemediationSteps(alert),
                references: this.extractReferences(alert),
                automated: false,
            },
            network: {
                protocol: urlParts.scheme?.toUpperCase() || 'HTTP',
                direction: 'inbound',
                transport: 'tcp',
            },
            status: 'open',
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity, this.mapExploitability(alert)),
            raw: alert,
        };
    }
    extractSeverity(finding) {
        const alert = finding;
        const mapping = {
            'Critical': 'critical',
            'High': 'high',
            'Medium': 'medium',
            'Low': 'low',
            'Informational': 'info',
        };
        return mapping[alert.risk] || 'medium';
    }
    mapConfidence(confidence) {
        const mapping = {
            'Confirmed': 'confirmed',
            'High': 'firm',
            'Medium': 'firm',
            'Low': 'tentative',
            'False Positive': 'tentative',
        };
        return mapping[confidence] || 'firm';
    }
    mapExploitability(alert) {
        if (alert.confidence === 'Confirmed' || alert.confidence === 'High') {
            return 'exploitable';
        }
        if (alert.confidence === 'Medium') {
            return 'potentially-exploitable';
        }
        return 'not-exploitable';
    }
    parseURL(url) {
        try {
            const urlObj = new URL(url);
            return {
                scheme: urlObj.protocol.replace(':', ''),
                domain: urlObj.hostname,
                port: urlObj.port ? parseInt(urlObj.port) : undefined,
                path: urlObj.pathname,
                query: urlObj.search.replace('?', ''),
                fragment: urlObj.hash.replace('#', ''),
            };
        }
        catch {
            return {};
        }
    }
    extractRemediationSteps(alert) {
        const steps = [];
        if (alert.solution) {
            steps.push(alert.solution);
        }
        if (alert.param) {
            steps.push(`Review and sanitize parameter: ${alert.param}`);
        }
        if (alert.attack) {
            steps.push(`Prevent attack pattern: ${alert.attack}`);
        }
        return steps.length > 0 ? steps : ['Review and fix the security issue'];
    }
    extractReferences(alert) {
        const refs = [];
        if (alert.cweid) {
            refs.push(`https://cwe.mitre.org/data/definitions/${alert.cweid}.html`);
        }
        if (alert.reference) {
            refs.push(alert.reference);
        }
        if (alert.wascid) {
            refs.push(`https://webappsec.org/wasc/${alert.wascid}`);
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
exports.OWASPZAPAdapter = OWASPZAPAdapter;
//# sourceMappingURL=owasp-zap-adapter.js.map