"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FindingCorrelationEngine = void 0;
class FindingCorrelationEngine {
    constructor(config) {
        this.config = {
            enabled: true,
            crossScannerDeduplication: {
                enabled: true,
                similarityThreshold: 0.85,
                strategies: ['cve', 'cwe', 'location', 'asset'],
                ...config?.crossScannerDeduplication,
            },
            relatedFindingGrouping: {
                enabled: true,
                maxDistance: 3,
                groupingStrategies: ['cwe-chain', 'asset-chain', 'dependency-chain', 'attack-path'],
                ...config?.relatedFindingGrouping,
            },
            rootCauseAnalysis: {
                enabled: true,
                maxDepth: 5,
                ...config?.rootCauseAnalysis,
            },
            impactAnalysis: {
                enabled: true,
                considerAssetCriticality: true,
                considerBusinessImpact: true,
                ...config?.impactAnalysis,
            },
            ...config,
        };
        this.findingsIndex = new Map();
        this.assetIndex = new Map();
        this.cveIndex = new Map();
        this.cweIndex = new Map();
    }
    async correlate(findings) {
        if (!this.config.enabled) {
            return {
                findings,
                groups: [],
                rootCauses: new Map(),
                impacts: new Map(),
                duplicates: new Map(),
                statistics: {
                    totalFindings: findings.length,
                    uniqueFindings: findings.length,
                    duplicateCount: 0,
                    groupCount: 0,
                    averageGroupSize: 0,
                },
            };
        }
        this.buildIndices(findings);
        let deduplicatedFindings = findings;
        const duplicates = new Map();
        if (this.config.crossScannerDeduplication.enabled) {
            const dedupResult = this.crossScannerDeduplication(findings);
            deduplicatedFindings = dedupResult.findings;
            dedupResult.duplicates.forEach((primary, duplicate) => {
                duplicates.set(duplicate, primary);
            });
        }
        const groups = [];
        if (this.config.relatedFindingGrouping.enabled) {
            groups.push(...this.groupRelatedFindings(deduplicatedFindings));
        }
        const rootCauses = new Map();
        if (this.config.rootCauseAnalysis.enabled) {
            for (const finding of deduplicatedFindings) {
                const analysis = this.analyzeRootCause(finding, deduplicatedFindings);
                if (analysis) {
                    rootCauses.set(finding.id, analysis);
                }
            }
        }
        const impacts = new Map();
        if (this.config.impactAnalysis.enabled) {
            for (const finding of deduplicatedFindings) {
                const impact = this.analyzeImpact(finding, deduplicatedFindings, groups);
                impacts.set(finding.id, impact);
            }
        }
        const correlatedFindings = this.enrichFindingsWithCorrelation(deduplicatedFindings, groups, rootCauses, impacts, duplicates);
        const statistics = {
            totalFindings: findings.length,
            uniqueFindings: correlatedFindings.length,
            duplicateCount: duplicates.size,
            groupCount: groups.length,
            averageGroupSize: groups.length > 0
                ? groups.reduce((sum, g) => sum + g.findings.length, 0) / groups.length
                : 0,
        };
        return {
            findings: correlatedFindings,
            groups,
            rootCauses,
            impacts,
            duplicates,
            statistics,
        };
    }
    buildIndices(findings) {
        this.findingsIndex.clear();
        this.assetIndex.clear();
        this.cveIndex.clear();
        this.cweIndex.clear();
        for (const finding of findings) {
            this.findingsIndex.set(finding.id, finding);
            const assetKey = this.getAssetKey(finding);
            if (assetKey) {
                if (!this.assetIndex.has(assetKey)) {
                    this.assetIndex.set(assetKey, []);
                }
                this.assetIndex.get(assetKey).push(finding);
            }
            const cveId = finding.vulnerability?.cve?.id || finding.vulnerability?.id;
            if (cveId) {
                if (!this.cveIndex.has(cveId)) {
                    this.cveIndex.set(cveId, []);
                }
                this.cveIndex.get(cveId).push(finding);
            }
            const cweId = finding.vulnerability?.classification;
            if (cweId && cweId.startsWith('CWE-')) {
                if (!this.cweIndex.has(cweId)) {
                    this.cweIndex.set(cweId, []);
                }
                this.cweIndex.get(cweId).push(finding);
            }
        }
    }
    crossScannerDeduplication(findings) {
        const unique = [];
        const duplicates = new Map();
        const processed = new Set();
        for (const finding of findings) {
            if (processed.has(finding.id)) {
                continue;
            }
            let isDuplicate = false;
            let primaryFinding = finding;
            for (const existing of unique) {
                const similarity = this.calculateSimilarity(finding, existing);
                if (similarity >= this.config.crossScannerDeduplication.similarityThreshold) {
                    primaryFinding = this.selectPrimaryFinding(finding, existing);
                    const duplicateFinding = primaryFinding.id === finding.id ? existing : finding;
                    duplicates.set(duplicateFinding.id, primaryFinding.id);
                    isDuplicate = true;
                    break;
                }
            }
            if (!isDuplicate) {
                unique.push(finding);
            }
            else {
                const primaryIndex = unique.findIndex(f => f.id === primaryFinding.id);
                if (primaryIndex >= 0) {
                    const duplicateFinding = finding.id === primaryFinding.id
                        ? findings.find(f => f.id !== primaryFinding.id && duplicates.get(f.id) === primaryFinding.id)
                        : finding;
                    if (duplicateFinding) {
                        unique[primaryIndex] = this.mergeFindingMetadata(unique[primaryIndex], duplicateFinding);
                    }
                }
            }
            processed.add(finding.id);
        }
        return { findings: unique, duplicates };
    }
    calculateSimilarity(f1, f2) {
        let score = 0;
        let maxScore = 0;
        const strategies = this.config.crossScannerDeduplication.strategies;
        if (strategies.includes('cve')) {
            const cve1 = f1.vulnerability?.cve?.id || f1.vulnerability?.id;
            const cve2 = f2.vulnerability?.cve?.id || f2.vulnerability?.id;
            if (cve1 && cve2) {
                maxScore += 0.4;
                if (cve1 === cve2) {
                    score += 0.4;
                }
            }
        }
        if (strategies.includes('cwe')) {
            const cwe1 = f1.vulnerability?.classification;
            const cwe2 = f2.vulnerability?.classification;
            if (cwe1 && cwe2) {
                maxScore += 0.2;
                if (cwe1 === cwe2) {
                    score += 0.2;
                }
            }
        }
        if (strategies.includes('location')) {
            maxScore += 0.2;
            const loc1 = this.getLocationKey(f1);
            const loc2 = this.getLocationKey(f2);
            if (loc1 && loc2 && loc1 === loc2) {
                score += 0.2;
            }
            else if (loc1 && loc2) {
                const similarity = this.locationSimilarity(loc1, loc2);
                score += 0.2 * similarity;
            }
        }
        if (strategies.includes('asset')) {
            maxScore += 0.2;
            const asset1 = this.getAssetKey(f1);
            const asset2 = this.getAssetKey(f2);
            if (asset1 && asset2 && asset1 === asset2) {
                score += 0.2;
            }
        }
        return maxScore > 0 ? score / maxScore : 0;
    }
    selectPrimaryFinding(f1, f2) {
        const severityOrder = {
            critical: 5,
            high: 4,
            medium: 3,
            low: 2,
            info: 1,
        };
        if (severityOrder[f1.severity] !== severityOrder[f2.severity]) {
            return severityOrder[f1.severity] > severityOrder[f2.severity] ? f1 : f2;
        }
        if (f1.riskScore !== f2.riskScore) {
            return f1.riskScore > f2.riskScore ? f1 : f2;
        }
        if (f1.createdAt !== f2.createdAt) {
            return f1.createdAt > f2.createdAt ? f1 : f2;
        }
        const sourceOrder = {
            sast: 5,
            dast: 4,
            sca: 3,
            container: 2,
            iac: 1,
        };
        if (sourceOrder[f1.source] !== sourceOrder[f2.source]) {
            return sourceOrder[f1.source] > sourceOrder[f2.source] ? f1 : f2;
        }
        return f1;
    }
    mergeFindingMetadata(primary, duplicate) {
        if (!primary.relatedFindings) {
            primary.relatedFindings = [];
        }
        if (!primary.relatedFindings.includes(duplicate.id)) {
            primary.relatedFindings.push(duplicate.id);
        }
        if (duplicate.scannerId !== primary.scannerId) {
            if (!primary.raw) {
                primary.raw = {};
            }
            if (!primary.raw.detectedByScanners) {
                primary.raw.detectedByScanners = [primary.scannerId];
            }
            if (!primary.raw.detectedByScanners.includes(duplicate.scannerId)) {
                primary.raw.detectedByScanners.push(duplicate.scannerId);
            }
        }
        return primary;
    }
    groupRelatedFindings(findings) {
        const groups = [];
        const processed = new Set();
        const strategies = this.config.relatedFindingGrouping.groupingStrategies;
        for (const finding of findings) {
            if (processed.has(finding.id)) {
                continue;
            }
            let group = null;
            if (strategies.includes('cwe-chain')) {
                group = this.groupByCWEChain(finding, findings, processed);
            }
            if (!group && strategies.includes('asset-chain')) {
                group = this.groupByAssetChain(finding, findings, processed);
            }
            if (!group && strategies.includes('dependency-chain')) {
                group = this.groupByDependencyChain(finding, findings, processed);
            }
            if (!group && strategies.includes('attack-path')) {
                group = this.groupByAttackPath(finding, findings, processed);
            }
            if (group) {
                groups.push(group);
                group.findings.forEach(id => processed.add(id));
            }
        }
        return groups;
    }
    groupByCWEChain(finding, allFindings, processed) {
        const cwe = finding.vulnerability?.classification;
        if (!cwe) {
            return null;
        }
        const related = allFindings.filter(f => {
            if (processed.has(f.id) || f.id === finding.id) {
                return false;
            }
            return f.vulnerability?.classification === cwe &&
                this.getAssetKey(f) === this.getAssetKey(finding);
        });
        if (related.length === 0) {
            return null;
        }
        return {
            id: `group-${finding.id}`,
            primaryFinding: finding.id,
            findings: [finding.id, ...related.map(f => f.id)],
            relationshipType: 'related',
            confidence: 0.8,
            impactScore: this.calculateGroupImpactScore([finding, ...related]),
            createdAt: new Date(),
        };
    }
    groupByAssetChain(finding, allFindings, processed) {
        const assetKey = this.getAssetKey(finding);
        if (!assetKey) {
            return null;
        }
        const related = this.assetIndex.get(assetKey)?.filter(f => {
            if (processed.has(f.id) || f.id === finding.id) {
                return false;
            }
            const severityOrder = {
                critical: 5,
                high: 4,
                medium: 3,
                low: 2,
                info: 1,
            };
            return Math.abs(severityOrder[f.severity] - severityOrder[finding.severity]) <= 1;
        }) || [];
        if (related.length === 0) {
            return null;
        }
        return {
            id: `group-${finding.id}`,
            primaryFinding: finding.id,
            findings: [finding.id, ...related.map(f => f.id)],
            relationshipType: 'cluster',
            confidence: 0.7,
            impactScore: this.calculateGroupImpactScore([finding, ...related]),
            createdAt: new Date(),
        };
    }
    groupByDependencyChain(finding, allFindings, processed) {
        const component = finding.asset.component;
        if (!component) {
            return null;
        }
        const related = allFindings.filter(f => {
            if (processed.has(f.id) || f.id === finding.id) {
                return false;
            }
            return f.asset.component === component &&
                f.asset.applicationId === finding.asset.applicationId;
        });
        if (related.length === 0) {
            return null;
        }
        return {
            id: `group-${finding.id}`,
            primaryFinding: finding.id,
            findings: [finding.id, ...related.map(f => f.id)],
            relationshipType: 'chain',
            confidence: 0.75,
            impactScore: this.calculateGroupImpactScore([finding, ...related]),
            createdAt: new Date(),
        };
    }
    groupByAttackPath(finding, allFindings, processed) {
        const cwe = finding.vulnerability?.classification;
        if (!cwe) {
            return null;
        }
        const attackChains = {
            'CWE-79': ['CWE-79', 'CWE-352'],
            'CWE-89': ['CWE-89', 'CWE-20'],
            'CWE-352': ['CWE-352', 'CWE-79'],
        };
        const chain = attackChains[cwe];
        if (!chain) {
            return null;
        }
        const related = allFindings.filter(f => {
            if (processed.has(f.id) || f.id === finding.id) {
                return false;
            }
            return chain.includes(f.vulnerability?.classification || '') &&
                f.asset.applicationId === finding.asset.applicationId;
        });
        if (related.length === 0) {
            return null;
        }
        return {
            id: `group-${finding.id}`,
            primaryFinding: finding.id,
            findings: [finding.id, ...related.map(f => f.id)],
            relationshipType: 'chain',
            confidence: 0.7,
            impactScore: this.calculateGroupImpactScore([finding, ...related]),
            createdAt: new Date(),
        };
    }
    analyzeRootCause(finding, allFindings) {
        const cwe = finding.vulnerability?.classification;
        if (!cwe) {
            return null;
        }
        const rootCauseCWEs = ['CWE-16', 'CWE-284', 'CWE-434', 'CWE-732'];
        const isLikelyRootCause = rootCauseCWEs.some(rc => cwe.includes(rc));
        if (isLikelyRootCause) {
            return {
                findingId: finding.id,
                rootCause: finding.id,
                chain: [finding.id],
                depth: 0,
                confidence: 0.8,
                analysis: {
                    type: this.determineRootCauseType(finding),
                    description: `This finding appears to be a root cause: ${finding.title}`,
                    evidence: [finding.description],
                },
            };
        }
        const related = this.findRelatedFindings(finding, allFindings);
        const rootCause = related.find(f => {
            const rc = f.vulnerability?.classification;
            return rc && rootCauseCWEs.some(cwe => rc.includes(cwe));
        });
        if (rootCause) {
            return {
                findingId: finding.id,
                rootCause: rootCause.id,
                chain: [rootCause.id, finding.id],
                depth: 1,
                confidence: 0.6,
                analysis: {
                    type: this.determineRootCauseType(rootCause),
                    description: `Root cause identified: ${rootCause.title}`,
                    evidence: [rootCause.description, finding.description],
                },
            };
        }
        return null;
    }
    determineRootCauseType(finding) {
        const cwe = finding.vulnerability?.classification || '';
        if (cwe.includes('CWE-16') || cwe.includes('CWE-284')) {
            return 'configuration';
        }
        if (finding.source === 'iac' || finding.source === 'cspm') {
            return 'infrastructure';
        }
        if (finding.source === 'sast' || finding.source === 'dast') {
            return 'code';
        }
        if (finding.source === 'sca' || finding.source === 'container') {
            return 'dependency';
        }
        return 'unknown';
    }
    findRelatedFindings(finding, allFindings) {
        const related = [];
        const assetKey = this.getAssetKey(finding);
        if (assetKey) {
            const sameAsset = this.assetIndex.get(assetKey) || [];
            related.push(...sameAsset.filter(f => f.id !== finding.id));
        }
        const cwe = finding.vulnerability?.classification;
        if (cwe) {
            const sameCWE = this.cweIndex.get(cwe) || [];
            related.push(...sameCWE.filter(f => f.id !== finding.id));
        }
        return related;
    }
    analyzeImpact(finding, allFindings, groups) {
        const severity = finding.severity === 'info' ? 'low' : finding.severity;
        const directImpact = {
            affectedAssets: [this.getAssetKey(finding)].filter(Boolean),
            affectedApplications: finding.asset.applicationId ? [finding.asset.applicationId] : [],
            severity: severity,
            businessImpact: finding.businessImpact || this.estimateBusinessImpact(finding),
        };
        const related = this.findRelatedFindings(finding, allFindings);
        const group = groups.find(g => g.findings.includes(finding.id));
        const potentialExploits = this.identifyPotentialExploits(finding, related);
        const complianceImpact = finding.compliance?.frameworks || [];
        const estimatedRemediationCost = this.estimateRemediationCost(finding, related.length);
        const cascadingImpact = {
            relatedFindings: related.map(f => f.id),
            potentialExploits,
            complianceImpact,
            estimatedRemediationCost,
        };
        const overallImpactScore = this.calculateOverallImpactScore(directImpact, cascadingImpact, group);
        return {
            findingId: finding.id,
            directImpact,
            cascadingImpact,
            overallImpactScore,
        };
    }
    estimateBusinessImpact(finding) {
        let score = 0;
        const severityScores = {
            critical: 90,
            high: 70,
            medium: 50,
            low: 30,
            info: 10,
        };
        score = severityScores[finding.severity] || 50;
        if (this.config.impactAnalysis.considerAssetCriticality) {
            if (finding.asset.applicationId) {
                score += 10;
            }
        }
        if (finding.compliance?.frameworks && finding.compliance.frameworks.length > 0) {
            score += finding.compliance.frameworks.length * 5;
        }
        return Math.min(100, score);
    }
    identifyPotentialExploits(finding, related) {
        const exploits = [];
        const cwe = finding.vulnerability?.classification;
        if (!cwe) {
            return exploits;
        }
        const exploitPatterns = {
            'CWE-79': ['XSS to session hijacking', 'XSS to credential theft'],
            'CWE-89': ['SQL injection to data breach', 'SQL injection to privilege escalation'],
            'CWE-352': ['CSRF to unauthorized actions', 'CSRF to account takeover'],
            'CWE-434': ['File upload to RCE', 'File upload to data exfiltration'],
        };
        const pattern = Object.keys(exploitPatterns).find(p => cwe.includes(p));
        if (pattern) {
            exploits.push(...exploitPatterns[pattern]);
        }
        const relatedCWEs = related.map(f => f.vulnerability?.classification).filter(Boolean);
        if (relatedCWEs.includes('CWE-352') && cwe.includes('CWE-79')) {
            exploits.push('XSS + CSRF chain to account takeover');
        }
        return exploits;
    }
    estimateRemediationCost(finding, relatedCount) {
        const baseCosts = {
            critical: 40,
            high: 20,
            medium: 10,
            low: 5,
            info: 2,
        };
        let cost = baseCosts[finding.severity] || 10;
        cost += relatedCount * 2;
        if (finding.remediation.estimatedEffort === 'high') {
            cost *= 1.5;
        }
        else if (finding.remediation.estimatedEffort === 'low') {
            cost *= 0.7;
        }
        return Math.round(cost);
    }
    calculateOverallImpactScore(direct, cascading, group) {
        let score = direct.businessImpact;
        if (cascading.relatedFindings.length > 0) {
            score += Math.min(20, cascading.relatedFindings.length * 2);
        }
        if (cascading.potentialExploits.length > 0) {
            score += cascading.potentialExploits.length * 5;
        }
        if (cascading.complianceImpact.length > 0) {
            score += cascading.complianceImpact.length * 3;
        }
        if (group) {
            score += group.impactScore * 0.1;
        }
        return Math.min(100, Math.round(score));
    }
    calculateGroupImpactScore(findings) {
        if (findings.length === 0) {
            return 0;
        }
        const maxSeverity = findings.reduce((max, f) => {
            const severityOrder = {
                critical: 5,
                high: 4,
                medium: 3,
                low: 2,
                info: 1,
            };
            return Math.max(max, severityOrder[f.severity] || 0);
        }, 0);
        const avgRiskScore = findings.reduce((sum, f) => sum + f.riskScore, 0) / findings.length;
        return Math.round((maxSeverity * 20) + (avgRiskScore * 0.6));
    }
    enrichFindingsWithCorrelation(findings, groups, rootCauses, impacts, duplicates) {
        return findings.map(finding => {
            const enriched = { ...finding };
            if (duplicates.has(finding.id)) {
                enriched.duplicateOf = duplicates.get(finding.id);
            }
            const group = groups.find(g => g.findings.includes(finding.id));
            if (group) {
                if (!enriched.relatedFindings) {
                    enriched.relatedFindings = [];
                }
                group.findings
                    .filter(id => id !== finding.id)
                    .forEach(id => {
                    if (!enriched.relatedFindings.includes(id)) {
                        enriched.relatedFindings.push(id);
                    }
                });
            }
            const rootCause = rootCauses.get(finding.id);
            if (rootCause && rootCause.rootCause !== finding.id) {
                if (!enriched.relatedFindings) {
                    enriched.relatedFindings = [];
                }
                if (!enriched.relatedFindings.includes(rootCause.rootCause)) {
                    enriched.relatedFindings.push(rootCause.rootCause);
                }
            }
            const impact = impacts.get(finding.id);
            if (impact) {
                if (!enriched.raw) {
                    enriched.raw = {};
                }
                enriched.raw.correlationImpact = {
                    overallImpactScore: impact.overallImpactScore,
                    affectedAssets: impact.directImpact.affectedAssets.length,
                    relatedFindingsCount: impact.cascadingImpact.relatedFindings.length,
                    potentialExploits: impact.cascadingImpact.potentialExploits.length,
                };
            }
            return enriched;
        });
    }
    getAssetKey(finding) {
        const parts = [];
        if (finding.asset.applicationId) {
            parts.push(finding.asset.applicationId);
        }
        if (finding.asset.component) {
            parts.push(finding.asset.component);
        }
        if (finding.asset.location?.file?.path) {
            parts.push(finding.asset.location.file.path);
        }
        else if (finding.asset.location?.url?.original) {
            parts.push(finding.asset.location.url.original);
        }
        else if (finding.asset.location?.resource) {
            parts.push(finding.asset.location.resource);
        }
        return parts.join('|') || finding.id;
    }
    getLocationKey(finding) {
        if (finding.asset.location?.file?.path) {
            return finding.asset.location.file.path;
        }
        if (finding.asset.location?.url?.original) {
            return finding.asset.location.url.original;
        }
        if (finding.asset.location?.resource) {
            return finding.asset.location.resource;
        }
        return null;
    }
    locationSimilarity(loc1, loc2) {
        if (loc1 === loc2) {
            return 1.0;
        }
        const path1 = loc1.split(':')[0];
        const path2 = loc2.split(':')[0];
        if (path1 === path2) {
            return 0.8;
        }
        const dir1 = path1.split('/').slice(0, -1).join('/');
        const dir2 = path2.split('/').slice(0, -1).join('/');
        if (dir1 === dir2 && dir1.length > 0) {
            return 0.5;
        }
        return 0;
    }
}
exports.FindingCorrelationEngine = FindingCorrelationEngine;
//# sourceMappingURL=finding-correlation-engine.js.map