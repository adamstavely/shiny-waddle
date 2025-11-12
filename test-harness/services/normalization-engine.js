"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.NormalizationEngine = void 0;
const sonarqube_adapter_1 = require("./scanner-adapters/sonarqube-adapter");
const snyk_adapter_1 = require("./scanner-adapters/snyk-adapter");
const owasp_zap_adapter_1 = require("./scanner-adapters/owasp-zap-adapter");
const checkov_adapter_1 = require("./scanner-adapters/checkov-adapter");
const trivy_adapter_1 = require("./scanner-adapters/trivy-adapter");
const aws_security_hub_adapter_1 = require("./scanner-adapters/aws-security-hub-adapter");
const ecs_adapter_1 = require("./ecs-adapter");
const schema_versioning_1 = require("../core/schema-versioning");
class NormalizationEngine {
    constructor(config) {
        this.config = {
            deduplication: {
                enabled: true,
                strategy: 'fuzzy',
                similarityThreshold: 0.8,
                ...config?.deduplication,
            },
            enrichment: {
                enabled: true,
                enrichCVE: true,
                enrichCWE: true,
                enrichCompliance: true,
                ...config?.enrichment,
            },
            validation: {
                enabled: true,
                strictMode: false,
                ...config?.validation,
            },
        };
        this.ecsAdapter = new ecs_adapter_1.ECSAdapter();
        this.adapters = new Map();
        this.initializeAdapters();
    }
    initializeAdapters() {
        this.adapters.set('sonarqube', new sonarqube_adapter_1.SonarQubeAdapter({}));
        this.adapters.set('snyk', new snyk_adapter_1.SnykAdapter({}, 'sca'));
        this.adapters.set('snyk-container', new snyk_adapter_1.SnykAdapter({}, 'container'));
        this.adapters.set('sonatype-iq', new (require('./scanner-adapters/sonatype-iq-adapter').SonatypeIQAdapter)({}));
        this.adapters.set('owasp-zap', new owasp_zap_adapter_1.OWASPZAPAdapter({}));
        this.adapters.set('checkov', new checkov_adapter_1.CheckovAdapter({}));
        this.adapters.set('trivy', new trivy_adapter_1.TrivyAdapter({}));
        this.adapters.set('clair', new (require('./scanner-adapters/clair-adapter').ClairAdapter)({}));
        this.adapters.set('aws-security-hub', new aws_security_hub_adapter_1.AWSSecurityHubAdapter({}));
    }
    registerAdapter(scannerId, adapter) {
        this.adapters.set(scannerId, adapter);
    }
    async normalize(scannerResults) {
        const allFindings = [];
        for (const result of scannerResults) {
            const adapter = this.adapters.get(result.scannerId);
            if (!adapter) {
                console.warn(`No adapter found for scanner: ${result.scannerId}`);
                continue;
            }
            try {
                const normalized = adapter.batchNormalize(result.findings, result.metadata);
                const migrated = normalized.map(f => (0, schema_versioning_1.normalizeToCurrentVersion)(f));
                allFindings.push(...migrated);
            }
            catch (error) {
                console.error(`Error normalizing findings from ${result.scannerId}:`, error);
            }
        }
        if (this.config.enrichment.enabled) {
            await this.enrichFindings(allFindings);
        }
        if (this.config.validation.enabled) {
            this.validateFindings(allFindings);
        }
        if (this.config.deduplication.enabled) {
            return this.deduplicateFindings(allFindings);
        }
        return allFindings;
    }
    async normalizeSingle(scannerId, findings, metadata) {
        const adapter = this.adapters.get(scannerId);
        if (!adapter) {
            throw new Error(`No adapter found for scanner: ${scannerId}`);
        }
        const normalized = adapter.batchNormalize(findings, metadata);
        const migrated = normalized.map(f => (0, schema_versioning_1.normalizeToCurrentVersion)(f));
        if (this.config.enrichment.enabled) {
            await this.enrichFindings(migrated);
        }
        if (this.config.validation.enabled) {
            this.validateFindings(migrated);
        }
        return migrated;
    }
    toECS(findings) {
        return this.ecsAdapter.batchToECS(findings);
    }
    fromECS(docs) {
        return this.ecsAdapter.batchFromECS(docs);
    }
    async enrichFindings(findings) {
        for (const finding of findings) {
            if (this.config.enrichment.enrichCVE && finding.vulnerability?.cve?.id) {
            }
            if (this.config.enrichment.enrichCWE && finding.vulnerability?.classification) {
            }
            if (this.config.enrichment.enrichCompliance && finding.vulnerability) {
                this.enrichComplianceMapping(finding);
            }
        }
    }
    enrichComplianceMapping(finding) {
        if (!finding.compliance) {
            finding.compliance = {
                frameworks: [],
                controls: [],
                requirements: [],
            };
        }
        const cveId = finding.vulnerability?.cve?.id;
        if (cveId) {
            if (finding.severity === 'critical' || finding.severity === 'high') {
                if (!finding.compliance.frameworks.includes('SOC2')) {
                    finding.compliance.frameworks.push('SOC2');
                }
                if (!finding.compliance.frameworks.includes('PCI-DSS')) {
                    finding.compliance.frameworks.push('PCI-DSS');
                }
            }
        }
        const cweId = finding.vulnerability?.classification;
        if (cweId && cweId.startsWith('CWE-')) {
            const cweNumber = cweId.replace('CWE-', '');
            if (['79', '89', '90'].includes(cweNumber)) {
                if (!finding.compliance.frameworks.includes('OWASP')) {
                    finding.compliance.frameworks.push('OWASP');
                }
            }
        }
    }
    validateFindings(findings) {
        for (const finding of findings) {
            const validation = (0, schema_versioning_1.validateSchemaVersion)(finding, schema_versioning_1.CURRENT_SCHEMA_VERSION);
            if (!validation.valid) {
                if (this.config.validation.strictMode) {
                    throw new Error(`Invalid finding ${finding.id}: ${validation.errors.join(', ')}`);
                }
                else {
                    console.warn(`Invalid finding ${finding.id}: ${validation.errors.join(', ')}`);
                }
            }
        }
    }
    deduplicateFindings(findings) {
        if (this.config.deduplication.strategy === 'exact') {
            return this.exactDeduplication(findings);
        }
        else if (this.config.deduplication.strategy === 'fuzzy') {
            return this.fuzzyDeduplication(findings);
        }
        else {
            return findings;
        }
    }
    exactDeduplication(findings) {
        const seen = new Map();
        const duplicates = [];
        for (const finding of findings) {
            const key = this.generateDeduplicationKey(finding);
            if (seen.has(key)) {
                const existing = seen.get(key);
                if (this.isMoreSevere(finding, existing) || finding.createdAt > existing.createdAt) {
                    duplicates.push(existing);
                    seen.set(key, finding);
                }
                else {
                    duplicates.push(finding);
                }
            }
            else {
                seen.set(key, finding);
            }
        }
        return Array.from(seen.values());
    }
    fuzzyDeduplication(findings) {
        const unique = [];
        const threshold = this.config.deduplication.similarityThreshold || 0.8;
        for (const finding of findings) {
            let isDuplicate = false;
            for (const existing of unique) {
                const similarity = this.calculateSimilarity(finding, existing);
                if (similarity >= threshold) {
                    if (this.isMoreSevere(finding, existing)) {
                        const index = unique.indexOf(existing);
                        unique[index] = finding;
                    }
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                unique.push(finding);
            }
        }
        return unique;
    }
    generateDeduplicationKey(finding) {
        const parts = [
            finding.vulnerability?.cve?.id || finding.vulnerability?.id || '',
            finding.scannerId,
            finding.asset.type,
            finding.asset.component || '',
            finding.asset.location?.file?.path || finding.asset.location?.url?.original || '',
        ];
        return parts.join('|');
    }
    calculateSimilarity(f1, f2) {
        let score = 0;
        let maxScore = 0;
        if (f1.vulnerability?.cve?.id && f2.vulnerability?.cve?.id) {
            if (f1.vulnerability.cve.id === f2.vulnerability.cve.id) {
                score += 0.4;
            }
            maxScore += 0.4;
        }
        if (f1.asset.component === f2.asset.component) {
            score += 0.3;
        }
        maxScore += 0.3;
        const loc1 = f1.asset.location?.file?.path || f1.asset.location?.url?.original || '';
        const loc2 = f2.asset.location?.file?.path || f2.asset.location?.url?.original || '';
        if (loc1 === loc2) {
            score += 0.2;
        }
        maxScore += 0.2;
        const title1 = f1.title.toLowerCase();
        const title2 = f2.title.toLowerCase();
        if (title1 === title2) {
            score += 0.1;
        }
        else if (this.stringSimilarity(title1, title2) > 0.7) {
            score += 0.05;
        }
        maxScore += 0.1;
        return maxScore > 0 ? score / maxScore : 0;
    }
    stringSimilarity(s1, s2) {
        const words1 = new Set(s1.split(/\s+/));
        const words2 = new Set(s2.split(/\s+/));
        const intersection = new Set([...words1].filter(x => words2.has(x)));
        const union = new Set([...words1, ...words2]);
        return union.size > 0 ? intersection.size / union.size : 0;
    }
    isMoreSevere(f1, f2) {
        const severityOrder = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1,
        };
        const s1 = severityOrder[f1.severity] || 0;
        const s2 = severityOrder[f2.severity] || 0;
        if (s1 !== s2) {
            return s1 > s2;
        }
        return f1.riskScore > f2.riskScore;
    }
}
exports.NormalizationEngine = NormalizationEngine;
//# sourceMappingURL=normalization-engine.js.map