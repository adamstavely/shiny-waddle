"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CheckovAdapter = void 0;
const base_adapter_1 = require("./base-adapter");
class CheckovAdapter extends base_adapter_1.BaseScannerAdapter {
    constructor(config) {
        super({
            scannerId: 'checkov',
            source: 'iac',
            enabled: true,
            config,
        });
    }
    validate(finding) {
        const check = finding;
        return !!(check.check_id &&
            check.check_name &&
            check.check_result &&
            check.file_path &&
            check.resource);
    }
    normalize(finding, metadata) {
        const check = finding;
        const severity = this.extractSeverity(check);
        const filePath = this.extractFilePath(check.file_path);
        return {
            id: this.generateFindingId(`${check.check_id}-${check.resource}`),
            event: {
                kind: 'event',
                category: 'compliance',
                type: 'compliance-violation',
                action: 'detected',
                severity: this.mapSeverityToECS(severity),
            },
            source: 'iac',
            scannerId: 'checkov',
            scannerFindingId: check.check_id,
            title: check.check_name,
            description: check.description || check.short_description || check.check_name,
            severity,
            confidence: 'firm',
            asset: {
                type: 'iac',
                applicationId: metadata?.applicationId,
                component: check.resource,
                location: {
                    file: {
                        name: filePath.name,
                        path: filePath.path,
                        extension: filePath.extension,
                        directory: filePath.directory,
                    },
                    line: check.file_line_range[0],
                    resource: check.resource,
                },
            },
            vulnerability: check.vulnerability_details ? {
                id: check.vulnerability_details.cve_id,
                classification: check.vulnerability_details.cwe_id,
                severity,
                scanner: {
                    vendor: 'Bridgecrew',
                    name: 'Checkov',
                    version: metadata?.checkovVersion,
                },
            } : undefined,
            compliance: {
                frameworks: this.extractFrameworks(check),
                controls: [check.check_id],
                requirements: [],
                rule: {
                    id: check.check_id,
                    name: check.check_name,
                    category: 'IaC',
                    description: check.guideline || check.description,
                },
            },
            remediation: {
                description: check.guideline || 'Review and fix the IaC configuration',
                steps: this.extractRemediationSteps(check),
                references: this.extractReferences(check),
                automated: !!check.fixed_definition,
            },
            status: check.check_result.result === 'FAILED' ? 'open' : 'resolved',
            createdAt: new Date(),
            updatedAt: new Date(),
            riskScore: this.calculateRiskScore(severity),
            raw: check,
        };
    }
    extractSeverity(finding) {
        const check = finding;
        if (check.severity) {
            const mapping = {
                'CRITICAL': 'critical',
                'HIGH': 'high',
                'MEDIUM': 'medium',
                'LOW': 'low',
            };
            return mapping[check.severity] || 'medium';
        }
        return 'medium';
    }
    extractFilePath(filePath) {
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
    extractFrameworks(check) {
        const frameworks = [];
        if (check.entity_tags) {
            if (check.entity_tags['framework']) {
                frameworks.push(check.entity_tags['framework']);
            }
            if (check.entity_tags['compliance']) {
                frameworks.push(...check.entity_tags['compliance'].split(','));
            }
        }
        if (check.check_id.includes('CKV_AWS') || check.check_id.includes('CKV2_AWS')) {
            frameworks.push('AWS-CIS');
        }
        if (check.check_id.includes('CKV_AZURE') || check.check_id.includes('CKV2_AZURE')) {
            frameworks.push('Azure-CIS');
        }
        if (check.check_id.includes('CKV_GCP') || check.check_id.includes('CKV2_GCP')) {
            frameworks.push('GCP-CIS');
        }
        return frameworks.length > 0 ? frameworks : ['IaC-Best-Practices'];
    }
    extractRemediationSteps(check) {
        const steps = [];
        if (check.fixed_definition) {
            steps.push('Apply the fixed definition provided by Checkov');
        }
        if (check.guideline) {
            steps.push(check.guideline);
        }
        if (check.check_result.evaluated_keys.length > 0) {
            steps.push(`Review and fix the following keys: ${check.check_result.evaluated_keys.join(', ')}`);
        }
        return steps.length > 0 ? steps : ['Review the IaC configuration and apply security best practices'];
    }
    extractReferences(check) {
        const refs = [];
        if (check.bc_check_id) {
            refs.push(`https://www.bridgecrew.cloud/r/policy/${check.bc_check_id}`);
        }
        if (check.vulnerability_details?.cve_id) {
            refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${check.vulnerability_details.cve_id}`);
        }
        if (check.vulnerability_details?.cwe_id) {
            refs.push(`https://cwe.mitre.org/data/definitions/${check.vulnerability_details.cwe_id.replace('CWE-', '')}.html`);
        }
        refs.push(`https://www.checkov.io/5.Policy%20Index/${check.check_id}.html`);
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
exports.CheckovAdapter = CheckovAdapter;
//# sourceMappingURL=checkov-adapter.js.map