"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.EnhancedRiskScorer = void 0;
class EnhancedRiskScorer {
    constructor(config, assetCriticality) {
        this.historicalScores = new Map();
        this.config = {
            weights: {
                severity: 0.20,
                exploitability: 0.15,
                assetCriticality: 0.15,
                exposure: 0.10,
                dataSensitivity: 0.10,
                complianceImpact: 0.10,
                businessImpact: 0.10,
                remediationComplexity: -0.05,
                age: 0.05,
                threatIntelligence: 0.10,
            },
            slaThresholds: {
                critical: 1,
                high: 7,
                medium: 30,
                low: 90,
            },
            ...config,
        };
        this.assetCriticality = {
            applications: {},
            componentPatterns: [
                { pattern: /auth|login|session/i, criticality: 'critical' },
                { pattern: /payment|billing|transaction/i, criticality: 'critical' },
                { pattern: /user|profile|account/i, criticality: 'high' },
                { pattern: /api\/v1\/admin/i, criticality: 'critical' },
                { pattern: /api\/public/i, criticality: 'high' },
            ],
            defaultByType: {
                application: 'high',
                infrastructure: 'medium',
                dependency: 'medium',
                container: 'high',
                iac: 'medium',
                api: 'high',
            },
            ...assetCriticality,
        };
    }
    calculateRiskScore(finding) {
        const baseScore = this.extractBaseScore(finding);
        const factors = this.calculateFactors(finding);
        const age = this.calculateAge(finding);
        const trend = this.calculateTrend(finding);
        const threatIntelligence = this.assessThreatIntelligence(finding);
        const adjustedScore = this.adjustScore(baseScore, factors, age, threatIntelligence);
        const { priority, reason } = this.calculatePriority(finding, factors, adjustedScore, age, threatIntelligence);
        const riskScore = {
            findingId: finding.id,
            baseScore,
            adjustedScore,
            factors,
            age,
            trend,
            threatIntelligence,
            priority,
            priorityReason: reason,
            calculatedAt: new Date(),
            version: '1.0.0',
        };
        this.storeHistoricalScore(finding.id, riskScore);
        return riskScore;
    }
    calculateRiskScores(findings) {
        return findings.map(finding => this.calculateRiskScore(finding));
    }
    prioritizeFindings(findings, riskScores) {
        const scores = riskScores || this.calculateRiskScores(findings);
        const combined = findings.map(finding => ({
            finding,
            riskScore: scores.find(s => s.findingId === finding.id),
        }));
        return combined.sort((a, b) => {
            if (b.riskScore.priority !== a.riskScore.priority) {
                return b.riskScore.priority - a.riskScore.priority;
            }
            if (b.riskScore.adjustedScore !== a.riskScore.adjustedScore) {
                return b.riskScore.adjustedScore - a.riskScore.adjustedScore;
            }
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
            return severityOrder[b.finding.severity] - severityOrder[a.finding.severity];
        });
    }
    aggregateByApplication(findings, applicationId) {
        const appFindings = findings.filter(f => f.asset.applicationId === applicationId);
        return this.aggregateRisks(appFindings, 'application', applicationId);
    }
    async aggregateByTeam(findings, teamName, getApplicationsByTeam) {
        const applications = await getApplicationsByTeam(teamName);
        const appIds = new Set(applications.map(app => app.id));
        const teamFindings = findings.filter(f => f.asset.applicationId && appIds.has(f.asset.applicationId));
        return this.aggregateRisks(teamFindings, 'team', teamName);
    }
    aggregateByOrganization(findings) {
        return this.aggregateRisks(findings, 'organization', 'organization');
    }
    getRiskTrends(findings, periodDays = 30) {
        const now = new Date();
        const periodStart = new Date(now.getTime() - periodDays * 24 * 60 * 60 * 1000);
        const trends = [];
        const dailyScores = new Map();
        for (const finding of findings) {
            if (finding.createdAt < periodStart)
                continue;
            const dateKey = finding.createdAt.toISOString().split('T')[0];
            const riskScore = this.calculateRiskScore(finding);
            const existing = dailyScores.get(dateKey) || { total: 0, count: 0 };
            existing.total += riskScore.adjustedScore;
            existing.count += 1;
            dailyScores.set(dateKey, existing);
        }
        for (const [dateKey, data] of dailyScores.entries()) {
            trends.push({
                date: new Date(dateKey),
                riskScore: data.count > 0 ? data.total / data.count : 0,
                count: data.count,
            });
        }
        return trends.sort((a, b) => a.date.getTime() - b.date.getTime());
    }
    extractBaseScore(finding) {
        if (finding.vulnerability?.cve?.score?.base) {
            return finding.vulnerability.cve.score.base * 10;
        }
        if (finding.riskScore !== undefined) {
            return finding.riskScore;
        }
        const severityScores = {
            critical: 90,
            high: 70,
            medium: 50,
            low: 30,
            info: 10,
        };
        return severityScores[finding.severity] || 50;
    }
    calculateFactors(finding) {
        return {
            severity: this.calculateSeverityFactor(finding),
            exploitability: this.calculateExploitabilityFactor(finding),
            assetCriticality: this.calculateAssetCriticalityFactor(finding),
            exposure: this.calculateExposureFactor(finding),
            dataSensitivity: this.calculateDataSensitivityFactor(finding),
            complianceImpact: this.calculateComplianceImpactFactor(finding),
            businessImpact: this.calculateBusinessImpactFactor(finding),
            remediationComplexity: this.calculateRemediationComplexityFactor(finding),
        };
    }
    calculateSeverityFactor(finding) {
        const severityScores = {
            critical: 100,
            high: 75,
            medium: 50,
            low: 25,
            info: 10,
        };
        return severityScores[finding.severity] || 50;
    }
    calculateExploitabilityFactor(finding) {
        if (finding.vulnerability?.cve?.score?.vector) {
            const vector = finding.vulnerability.cve.score.vector;
            if (vector.includes('AV:N') && vector.includes('AC:L')) {
                return 90;
            }
            if (vector.includes('AV:N')) {
                return 70;
            }
            if (vector.includes('AV:L')) {
                return 50;
            }
        }
        if (finding.confidence === 'confirmed') {
            return 80;
        }
        const severityExploitability = {
            critical: 85,
            high: 70,
            medium: 50,
            low: 30,
            info: 10,
        };
        return severityExploitability[finding.severity] || 50;
    }
    calculateAssetCriticalityFactor(finding) {
        const appId = finding.asset.applicationId;
        if (appId && this.assetCriticality.applications[appId]) {
            const crit = this.assetCriticality.applications[appId];
            const criticalityScores = {
                critical: 100,
                high: 75,
                medium: 50,
                low: 25,
            };
            return criticalityScores[crit];
        }
        const component = finding.asset.component || '';
        const location = finding.asset.location;
        const fullPath = location?.file?.path || location?.url?.path || component;
        for (const pattern of this.assetCriticality.componentPatterns) {
            if (pattern.pattern.test(fullPath)) {
                const criticalityScores = {
                    critical: 100,
                    high: 75,
                    medium: 50,
                    low: 25,
                };
                return criticalityScores[pattern.criticality];
            }
        }
        const defaultCrit = this.assetCriticality.defaultByType[finding.asset.type] || 'medium';
        const criticalityScores = {
            critical: 100,
            high: 75,
            medium: 50,
            low: 25,
        };
        return criticalityScores[defaultCrit];
    }
    calculateExposureFactor(finding) {
        const location = finding.asset.location;
        if (location?.url) {
            const url = location.url;
            if (url.path?.includes('/public') || url.path?.includes('/api/public')) {
                return 90;
            }
            if (url.path?.includes('/admin') || url.path?.includes('/api/admin')) {
                return 70;
            }
            if (url.path?.includes('/internal') || url.path?.includes('/api/internal')) {
                return 40;
            }
            return 60;
        }
        if (finding.asset.type === 'infrastructure' || finding.asset.type === 'iac') {
            const resource = location?.resource || '';
            if (resource.includes('s3') || resource.includes('bucket')) {
                return 80;
            }
            if (resource.includes('public') || resource.includes('external')) {
                return 70;
            }
            return 50;
        }
        if (finding.asset.type === 'container') {
            return 60;
        }
        return 40;
    }
    calculateDataSensitivityFactor(finding) {
        if (finding.compliance?.frameworks) {
            const sensitiveFrameworks = ['HIPAA', 'PCI-DSS', 'GDPR'];
            const hasSensitive = finding.compliance.frameworks.some(f => sensitiveFrameworks.includes(f));
            if (hasSensitive) {
                return 90;
            }
        }
        const title = finding.title.toLowerCase();
        const description = finding.description.toLowerCase();
        const piiKeywords = ['pii', 'ssn', 'credit card', 'password', 'secret', 'token', 'api key'];
        if (piiKeywords.some(keyword => title.includes(keyword) || description.includes(keyword))) {
            return 85;
        }
        if (finding.vulnerability?.classification) {
            const classification = finding.vulnerability.classification.toLowerCase();
            if (classification.includes('cwe-359') || classification.includes('privacy')) {
                return 80;
            }
        }
        const severitySensitivity = {
            critical: 70,
            high: 60,
            medium: 40,
            low: 20,
            info: 10,
        };
        return severitySensitivity[finding.severity] || 40;
    }
    calculateComplianceImpactFactor(finding) {
        if (!finding.compliance?.frameworks || finding.compliance.frameworks.length === 0) {
            return 0;
        }
        let impact = 0;
        const frameworkWeights = {
            'SOC 2': 20,
            'PCI-DSS': 30,
            'HIPAA': 30,
            'GDPR': 25,
            'ISO 27001': 20,
            'NIST': 25,
        };
        for (const framework of finding.compliance.frameworks) {
            impact += frameworkWeights[framework] || 15;
        }
        if (finding.compliance.controls && finding.compliance.controls.length > 0) {
            impact += 10 * finding.compliance.controls.length;
        }
        return Math.min(100, impact);
    }
    calculateBusinessImpactFactor(finding) {
        if (finding.businessImpact !== undefined) {
            return finding.businessImpact;
        }
        const assetCrit = this.calculateAssetCriticalityFactor(finding);
        const exposure = this.calculateExposureFactor(finding);
        const dataSensitivity = this.calculateDataSensitivityFactor(finding);
        return (assetCrit * 0.4) + (exposure * 0.3) + (dataSensitivity * 0.3);
    }
    calculateRemediationComplexityFactor(finding) {
        const remediation = finding.remediation;
        if (remediation.automated) {
            return 20;
        }
        if (remediation.estimatedEffort) {
            const effortScores = {
                low: 30,
                medium: 60,
                high: 90,
            };
            return effortScores[remediation.estimatedEffort] || 50;
        }
        const stepCount = remediation.steps?.length || 0;
        if (stepCount === 0) {
            return 50;
        }
        if (stepCount <= 2) {
            return 30;
        }
        if (stepCount <= 5) {
            return 60;
        }
        return 90;
    }
    calculateAge(finding) {
        const detectedDate = finding.detectedAt || finding.createdAt;
        const now = new Date();
        const diffTime = now.getTime() - detectedDate.getTime();
        return Math.floor(diffTime / (1000 * 60 * 60 * 24));
    }
    calculateTrend(finding) {
        const historical = this.historicalScores.get(finding.id) || [];
        if (historical.length < 2) {
            return 'stable';
        }
        const recent = historical.slice(-2);
        const change = recent[1].adjustedScore - recent[0].adjustedScore;
        if (change > 5) {
            return 'increasing';
        }
        else if (change < -5) {
            return 'decreasing';
        }
        return 'stable';
    }
    assessThreatIntelligence(finding) {
        const cveId = finding.vulnerability?.cve?.id || finding.vulnerability?.id;
        if (!cveId) {
            return undefined;
        }
        const title = finding.title.toLowerCase();
        const description = finding.description.toLowerCase();
        const hasActiveExploit = title.includes('exploit') ||
            title.includes('active') ||
            description.includes('exploit in the wild');
        const hasRansomware = title.includes('ransomware') ||
            description.includes('ransomware');
        let threatActorInterest = 'low';
        if (finding.severity === 'critical' || finding.severity === 'high') {
            if (hasActiveExploit || hasRansomware) {
                threatActorInterest = 'high';
            }
            else {
                threatActorInterest = 'medium';
            }
        }
        return {
            activeExploits: hasActiveExploit,
            exploitInWild: hasActiveExploit,
            ransomware: hasRansomware,
            threatActorInterest,
        };
    }
    adjustScore(baseScore, factors, age, threatIntelligence) {
        let adjusted = baseScore;
        const weights = this.config.weights;
        adjusted += (factors.severity - 50) * weights.severity;
        adjusted += (factors.exploitability - 50) * weights.exploitability;
        adjusted += (factors.assetCriticality - 50) * weights.assetCriticality;
        adjusted += (factors.exposure - 50) * weights.exposure;
        adjusted += (factors.dataSensitivity - 50) * weights.dataSensitivity;
        adjusted += factors.complianceImpact * weights.complianceImpact;
        adjusted += factors.businessImpact * weights.businessImpact;
        adjusted -= factors.remediationComplexity * Math.abs(weights.remediationComplexity);
        if (age > this.config.slaThresholds.critical && baseScore > 70) {
            adjusted += age * 0.1;
        }
        if (threatIntelligence) {
            if (threatIntelligence.activeExploits || threatIntelligence.exploitInWild) {
                adjusted += 15;
            }
            if (threatIntelligence.ransomware) {
                adjusted += 20;
            }
            if (threatIntelligence.threatActorInterest === 'high') {
                adjusted += 10;
            }
        }
        return Math.max(0, Math.min(100, adjusted));
    }
    calculatePriority(finding, factors, adjustedScore, age, threatIntelligence) {
        let priority = adjustedScore;
        const reasons = [];
        const severity = finding.severity;
        const slaThreshold = this.config.slaThresholds[severity] || 30;
        if (age > slaThreshold) {
            const overdueDays = age - slaThreshold;
            priority += Math.min(20, overdueDays * 2);
            reasons.push(`Overdue by ${overdueDays} days (SLA: ${slaThreshold} days)`);
        }
        if (threatIntelligence?.activeExploits || threatIntelligence?.exploitInWild) {
            priority += 25;
            reasons.push('Active exploit in the wild');
        }
        if (threatIntelligence?.ransomware) {
            priority += 30;
            reasons.push('Ransomware threat');
        }
        if (factors.businessImpact > 70) {
            priority += 10;
            reasons.push('High business impact');
        }
        if (factors.complianceImpact > 50) {
            priority += 10;
            reasons.push('Compliance violation');
        }
        if (factors.remediationComplexity < 30) {
            priority += 5;
            reasons.push('Easy to remediate');
        }
        priority = Math.max(0, Math.min(100, priority));
        const reason = reasons.length > 0
            ? reasons.join('; ')
            : `Risk score: ${adjustedScore.toFixed(1)}`;
        return { priority, reason };
    }
    aggregateRisks(findings, level, identifier) {
        const riskScores = this.calculateRiskScores(findings);
        if (riskScores.length === 0) {
            return {
                level,
                identifier,
                totalFindings: 0,
                riskScore: 0,
                averageRiskScore: 0,
                maxRiskScore: 0,
                criticalCount: 0,
                highCount: 0,
                mediumCount: 0,
                lowCount: 0,
                trend: {
                    current: 0,
                    previous: 0,
                    change: 0,
                    direction: 'stable',
                },
                bySeverity: {
                    critical: 0,
                    high: 0,
                    medium: 0,
                    low: 0,
                },
                topRisks: [],
            };
        }
        const totalScore = riskScores.reduce((sum, rs) => sum + rs.adjustedScore, 0);
        const averageScore = totalScore / riskScores.length;
        const maxScore = Math.max(...riskScores.map(rs => rs.adjustedScore));
        const bySeverity = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        for (const finding of findings) {
            bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
        }
        const aggregatedScore = this.calculateAggregatedRiskScore(riskScores);
        const topRisks = riskScores
            .sort((a, b) => b.adjustedScore - a.adjustedScore)
            .slice(0, 10)
            .map(rs => {
            const finding = findings.find(f => f.id === rs.findingId);
            return {
                findingId: rs.findingId,
                riskScore: rs.adjustedScore,
                title: finding.title,
            };
        });
        const now = new Date();
        const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
        const recentFindings = findings.filter(f => f.createdAt >= thirtyDaysAgo);
        const olderFindings = findings.filter(f => f.createdAt < thirtyDaysAgo);
        const currentScore = recentFindings.length > 0
            ? recentFindings.reduce((sum, f) => {
                const rs = riskScores.find(s => s.findingId === f.id);
                return sum + (rs?.adjustedScore || 0);
            }, 0) / recentFindings.length
            : 0;
        const previousScore = olderFindings.length > 0
            ? olderFindings.reduce((sum, f) => {
                const rs = riskScores.find(s => s.findingId === f.id);
                return sum + (rs?.adjustedScore || 0);
            }, 0) / olderFindings.length
            : 0;
        const change = previousScore > 0
            ? ((currentScore - previousScore) / previousScore) * 100
            : 0;
        return {
            level,
            identifier,
            totalFindings: findings.length,
            riskScore: aggregatedScore,
            averageRiskScore: averageScore,
            maxRiskScore: maxScore,
            criticalCount: bySeverity.critical,
            highCount: bySeverity.high,
            mediumCount: bySeverity.medium,
            lowCount: bySeverity.low,
            trend: {
                current: currentScore,
                previous: previousScore,
                change,
                direction: change > 5 ? 'increasing' : change < -5 ? 'decreasing' : 'stable',
            },
            bySeverity,
            topRisks,
        };
    }
    calculateAggregatedRiskScore(riskScores) {
        if (riskScores.length === 0)
            return 0;
        const severityWeights = {
            critical: 1.0,
            high: 0.75,
            medium: 0.5,
            low: 0.25,
            info: 0.1,
        };
        let weightedSum = 0;
        let totalWeight = 0;
        for (const rs of riskScores) {
            const weight = 1.0;
            weightedSum += rs.adjustedScore * weight;
            totalWeight += weight;
        }
        return totalWeight > 0 ? weightedSum / totalWeight : 0;
    }
    storeHistoricalScore(findingId, score) {
        const historical = this.historicalScores.get(findingId) || [];
        historical.push(score);
        if (historical.length > 30) {
            historical.shift();
        }
        this.historicalScores.set(findingId, historical);
    }
    updateAssetCriticality(config) {
        this.assetCriticality = {
            ...this.assetCriticality,
            ...config,
            applications: {
                ...this.assetCriticality.applications,
                ...config.applications,
            },
            componentPatterns: [
                ...this.assetCriticality.componentPatterns,
                ...(config.componentPatterns || []),
            ],
        };
    }
    updateConfig(config) {
        this.config = {
            ...this.config,
            ...config,
            weights: {
                ...this.config.weights,
                ...config.weights,
            },
        };
    }
}
exports.EnhancedRiskScorer = EnhancedRiskScorer;
//# sourceMappingURL=enhanced-risk-scorer.js.map