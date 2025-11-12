"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SonarQubeAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class SonarQubeAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'sonarqube',
            source: 'sast',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const issue = finding;
        return !!(issue.key &&
            issue.rule &&
            issue.severity &&
            issue.component &&
            issue.message);
    }
    normalize(finding, metadata) {
        const issue = finding;
        const severity = this.extractSeverity(issue);
        const filePath = this.extractFilePath(issue.component);
        return {
            id: this.generateFindingId(issue.key),
            event: {
                kind: 'event',
                category: issue.type === 'VULNERABILITY' || issue.type === 'SECURITY_HOTSPOT' ? 'vulnerability' : 'security',
                type: 'vulnerability',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'sast',
            scannerId: 'sonarqube',
            scannerFindingId: issue.key,
            title: issue.message,
            description: issue.ruleDescription || issue.message,
            severity,
            confidence: 'firm',
            asset: {
                type: 'application',
                applicationId: metadata?.applicationId || issue.project,
                component: issue.component,
                location: {
                    file: {
                        name: filePath.name,
                        path: filePath.path,
                        extension: filePath.extension,
                        directory: filePath.directory,
                    },
                    line: issue.line || issue.textRange?.startLine,
                    column: issue.textRange?.startOffset,
                },
            },
            vulnerability: {
                id: issue.rule,
                classification: issue.rule,
                severity,
                scanner: {
                    vendor: 'SonarSource',
                    name: 'SonarQube',
                    version: metadata?.sonarVersion,
                },
            },
            remediation: {
                description: issue.remediation?.message || '',
                steps: issue.remediation?.func ? [issue.remediation.func] : [],
                references: [`https://rules.sonarsource.com/${issue.rule}`],
                automated: false,
            },
            status: this.mapStatus(issue.status),
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: issue,
        };
    }
    extractSeverity(finding) {
        const issue = finding;
        const mapping = {
            'BLOCKER': 'critical',
            'CRITICAL': 'high',
            'MAJOR': 'medium',
            'MINOR': 'low',
            'INFO': 'info',
        };
        return mapping[issue.severity] || 'medium';
    }
    extractFilePath(component) {
        const parts = component.split(':');
        const filePath = parts[parts.length - 1] || component;
        const pathParts = filePath.split('/');
        const fileName = pathParts[pathParts.length - 1] || filePath;
        const extMatch = fileName.match(/\.([^.]+)$/);
        const extension = extMatch ? extMatch[1] : '';
        const directory = pathParts.slice(0, -1).join('/');
        return {
            name: fileName,
            path: filePath,
            extension,
            directory,
        };
    }
    mapStatus(status) {
        if (!status)
            return 'open';
        const mapping = {
            'OPEN': 'open',
            'CONFIRMED': 'open',
            'REOPENED': 'open',
            'RESOLVED': 'resolved',
            'CLOSED': 'resolved',
            'FALSE-POSITIVE': 'false-positive',
            'WONTFIX': 'risk-accepted',
        };
        return mapping[status.toUpperCase()] || 'open';
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
exports.SonarQubeAdapter = SonarQubeAdapter;
//# sourceMappingURL=sonarqube-adapter.js.map