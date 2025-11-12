"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.AnomalyDetectionService = void 0;
const events_1 = require("events");
class AnomalyDetectionService extends events_1.EventEmitter {
    constructor(config = {}) {
        super();
        this.findingHistory = [];
        this.riskBaselines = new Map();
        this.complianceBaselines = new Map();
        this.patternHistory = [];
        this.maxHistorySize = 10000;
        this.config = {
            enableUnusualPatterns: config.enableUnusualPatterns !== false,
            enableRiskSpikeDetection: config.enableRiskSpikeDetection !== false,
            enableComplianceDriftDetection: config.enableComplianceDriftDetection !== false,
            enableAttackPatternDetection: config.enableAttackPatternDetection !== false,
            riskSpikeThreshold: config.riskSpikeThreshold || 50,
            complianceDriftThreshold: config.complianceDriftThreshold || 10,
            timeWindow: config.timeWindow || 3600000,
            minFindingsForPattern: config.minFindingsForPattern || 5,
        };
    }
    async analyzeFindings(findings) {
        const anomalies = [];
        this.findingHistory.push(...findings);
        if (this.findingHistory.length > this.maxHistorySize) {
            this.findingHistory = this.findingHistory.slice(-this.maxHistorySize);
        }
        if (this.config.enableUnusualPatterns) {
            const patternAnomalies = await this.detectUnusualPatterns(findings);
            anomalies.push(...patternAnomalies);
        }
        if (this.config.enableRiskSpikeDetection) {
            const riskSpikes = await this.detectRiskSpikes(findings);
            anomalies.push(...riskSpikes);
        }
        if (this.config.enableComplianceDriftDetection) {
            const complianceDrifts = await this.detectComplianceDrift(findings);
            anomalies.push(...complianceDrifts);
        }
        if (this.config.enableAttackPatternDetection) {
            const attackPatterns = await this.detectAttackPatterns(findings);
            anomalies.push(...attackPatterns);
        }
        anomalies.forEach(anomaly => {
            this.emit('anomaly_detected', anomaly);
        });
        return anomalies;
    }
    async detectUnusualPatterns(findings) {
        const anomalies = [];
        const timeWindow = this.config.timeWindow || 3600000;
        const now = Date.now();
        const windowStart = new Date(now - timeWindow);
        const patterns = new Map();
        for (const finding of findings) {
            const key = `${finding.scannerId}-${finding.severity}-${finding.asset.applicationId || 'unknown'}`;
            const pattern = patterns.get(key) || {
                scannerId: finding.scannerId,
                severity: finding.severity,
                applicationId: finding.asset.applicationId,
                component: finding.asset.component,
                count: 0,
                trend: 'stable',
                changeRate: 0,
            };
            pattern.count++;
            patterns.set(key, pattern);
        }
        const historicalPatterns = this.patternHistory.filter(p => new Date(p.count) >= windowStart);
        for (const [key, pattern] of patterns) {
            const historical = historicalPatterns.find(p => p.scannerId === pattern.scannerId &&
                p.severity === pattern.severity &&
                p.applicationId === pattern.applicationId);
            if (historical) {
                const changeRate = ((pattern.count - historical.count) / historical.count) * 100;
                pattern.changeRate = changeRate;
                pattern.trend = changeRate > 20 ? 'increasing' : changeRate < -20 ? 'decreasing' : 'stable';
                if (changeRate > 100 && pattern.count >= (this.config.minFindingsForPattern || 5)) {
                    const relatedFindings = findings.filter(f => f.scannerId === pattern.scannerId &&
                        f.severity === pattern.severity &&
                        f.asset.applicationId === pattern.applicationId);
                    anomalies.push({
                        id: `anomaly-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                        type: 'unusual_pattern',
                        severity: this.mapChangeRateToSeverity(changeRate),
                        title: `Unusual pattern detected: ${pattern.scannerId} findings increased by ${changeRate.toFixed(1)}%`,
                        description: `Found ${pattern.count} ${pattern.severity} findings from ${pattern.scannerId} in the last ${timeWindow / 1000 / 60} minutes, representing a ${changeRate.toFixed(1)}% increase.`,
                        detectedAt: new Date(),
                        findings: relatedFindings,
                        metrics: {
                            pattern,
                            changeRate,
                            historicalCount: historical.count,
                            currentCount: pattern.count,
                        },
                        confidence: Math.min(changeRate / 200, 1),
                    });
                }
            }
        }
        this.patternHistory.push(...Array.from(patterns.values()));
        if (this.patternHistory.length > 1000) {
            this.patternHistory = this.patternHistory.slice(-1000);
        }
        return anomalies;
    }
    async detectRiskSpikes(findings) {
        const anomalies = [];
        const threshold = this.config.riskSpikeThreshold || 50;
        const appRisks = new Map();
        for (const finding of findings) {
            const appId = finding.asset.applicationId || 'unknown';
            const current = appRisks.get(appId) || { findings: [], totalRisk: 0 };
            current.findings.push(finding);
            current.totalRisk += finding.riskScore || 0;
            appRisks.set(appId, current);
        }
        for (const [appId, data] of appRisks) {
            const baseline = this.riskBaselines.get(appId) || data.totalRisk;
            const currentRisk = data.totalRisk;
            const increase = ((currentRisk - baseline) / baseline) * 100;
            if (increase >= threshold) {
                const timeWindow = this.config.timeWindow || 3600000;
                anomalies.push({
                    id: `risk-spike-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    type: 'risk_spike',
                    severity: this.mapRiskIncreaseToSeverity(increase),
                    title: `Risk spike detected for application: ${appId}`,
                    description: `Application risk increased by ${increase.toFixed(1)}% from baseline of ${baseline.toFixed(0)} to ${currentRisk.toFixed(0)}.`,
                    detectedAt: new Date(),
                    findings: data.findings,
                    metrics: {
                        baselineRisk: baseline,
                        currentRisk,
                        increase,
                        applicationId: appId,
                    },
                    confidence: Math.min(increase / (threshold * 2), 1),
                    metadata: {
                        timeWindow: {
                            start: new Date(Date.now() - timeWindow),
                            end: new Date(),
                        },
                    },
                });
                this.riskBaselines.set(appId, currentRisk);
            }
            else {
                const newBaseline = baseline * 0.9 + currentRisk * 0.1;
                this.riskBaselines.set(appId, newBaseline);
            }
        }
        return anomalies;
    }
    async detectComplianceDrift(findings) {
        const anomalies = [];
        const threshold = this.config.complianceDriftThreshold || 10;
        const frameworkFindings = new Map();
        for (const finding of findings) {
            if (finding.compliance?.frameworks) {
                for (const framework of finding.compliance.frameworks) {
                    const current = frameworkFindings.get(framework) || [];
                    current.push(finding);
                    frameworkFindings.set(framework, current);
                }
            }
        }
        for (const [framework, frameworkFindingsList] of frameworkFindings) {
            const totalControls = 100;
            const nonCompliantControls = frameworkFindingsList.filter(f => f.status === 'open').length;
            const currentCompliance = ((totalControls - nonCompliantControls) / totalControls) * 100;
            const baseline = this.complianceBaselines.get(framework) || currentCompliance;
            const decrease = baseline - currentCompliance;
            if (decrease >= threshold) {
                const timeWindow = this.config.timeWindow || 3600000;
                anomalies.push({
                    id: `compliance-drift-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                    type: 'compliance_drift',
                    severity: this.mapComplianceDecreaseToSeverity(decrease),
                    title: `Compliance drift detected for ${framework}`,
                    description: `Compliance for ${framework} decreased by ${decrease.toFixed(1)}% from ${baseline.toFixed(1)}% to ${currentCompliance.toFixed(1)}%.`,
                    detectedAt: new Date(),
                    findings: frameworkFindingsList,
                    metrics: {
                        framework,
                        baselineCompliance: baseline,
                        currentCompliance,
                        decrease,
                        nonCompliantControls,
                    },
                    confidence: Math.min(decrease / (threshold * 2), 1),
                    metadata: {
                        timeWindow: {
                            start: new Date(Date.now() - timeWindow),
                            end: new Date(),
                        },
                    },
                });
                this.complianceBaselines.set(framework, currentCompliance);
            }
            else {
                const newBaseline = baseline * 0.95 + currentCompliance * 0.05;
                this.complianceBaselines.set(framework, newBaseline);
            }
        }
        return anomalies;
    }
    async detectAttackPatterns(findings) {
        const anomalies = [];
        const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
        if (criticalFindings.length >= 10) {
            const scannerCounts = new Map();
            criticalFindings.forEach(f => {
                scannerCounts.set(f.scannerId, (scannerCounts.get(f.scannerId) || 0) + 1);
            });
            for (const [scannerId, count] of scannerCounts) {
                if (count >= 5) {
                    const relatedFindings = criticalFindings.filter(f => f.scannerId === scannerId);
                    anomalies.push({
                        id: `attack-pattern-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                        type: 'attack_pattern',
                        severity: 'critical',
                        title: `Potential mass exploitation detected: ${count} critical/high findings from ${scannerId}`,
                        description: `Detected ${count} critical or high severity findings from ${scannerId} in a short time window, indicating potential mass exploitation attempt.`,
                        detectedAt: new Date(),
                        findings: relatedFindings,
                        metrics: {
                            pattern: 'mass-exploitation',
                            scannerId,
                            count,
                            indicators: ['multiple-critical-findings', 'same-scanner', 'short-time-window'],
                        },
                        confidence: Math.min(count / 20, 1),
                        metadata: {
                            pattern: 'mass-exploitation',
                            indicators: ['multiple-critical-findings', 'same-scanner', 'short-time-window'],
                        },
                    });
                }
            }
        }
        const appFindings = new Map();
        findings.forEach(f => {
            const appId = f.asset.applicationId || 'unknown';
            const current = appFindings.get(appId) || [];
            current.push(f);
            appFindings.set(appId, current);
        });
        if (appFindings.size >= 5) {
            const allFindings = Array.from(appFindings.values()).flat();
            anomalies.push({
                id: `attack-pattern-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                type: 'attack_pattern',
                severity: 'high',
                title: `Potential lateral movement detected across ${appFindings.size} applications`,
                description: `Detected security findings across ${appFindings.size} different applications, indicating potential lateral movement.`,
                detectedAt: new Date(),
                findings: allFindings,
                metrics: {
                    pattern: 'lateral-movement',
                    applicationCount: appFindings.size,
                    indicators: ['multiple-applications', 'similar-findings', 'short-time-window'],
                },
                confidence: Math.min(appFindings.size / 10, 1),
                metadata: {
                    pattern: 'lateral-movement',
                    indicators: ['multiple-applications', 'similar-findings', 'short-time-window'],
                },
            });
        }
        const sensitiveFindings = findings.filter(f => f.title.toLowerCase().includes('pii') ||
            f.title.toLowerCase().includes('sensitive') ||
            f.title.toLowerCase().includes('credential') ||
            f.description.toLowerCase().includes('data leak'));
        if (sensitiveFindings.length >= 3) {
            anomalies.push({
                id: `attack-pattern-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                type: 'attack_pattern',
                severity: 'critical',
                title: `Potential data exfiltration detected: ${sensitiveFindings.length} sensitive data findings`,
                description: `Detected ${sensitiveFindings.length} findings related to sensitive data exposure, indicating potential data exfiltration attempt.`,
                detectedAt: new Date(),
                findings: sensitiveFindings,
                metrics: {
                    pattern: 'data-exfiltration',
                    count: sensitiveFindings.length,
                    indicators: ['sensitive-data', 'multiple-findings', 'short-time-window'],
                },
                confidence: Math.min(sensitiveFindings.length / 10, 1),
                metadata: {
                    pattern: 'data-exfiltration',
                    indicators: ['sensitive-data', 'multiple-findings', 'short-time-window'],
                },
            });
        }
        return anomalies;
    }
    mapChangeRateToSeverity(changeRate) {
        if (changeRate >= 500)
            return 'critical';
        if (changeRate >= 200)
            return 'high';
        if (changeRate >= 100)
            return 'medium';
        return 'low';
    }
    mapRiskIncreaseToSeverity(increase) {
        if (increase >= 200)
            return 'critical';
        if (increase >= 100)
            return 'high';
        if (increase >= 50)
            return 'medium';
        return 'low';
    }
    mapComplianceDecreaseToSeverity(decrease) {
        if (decrease >= 30)
            return 'critical';
        if (decrease >= 20)
            return 'high';
        if (decrease >= 10)
            return 'medium';
        return 'low';
    }
    getStats() {
        return {
            historySize: this.findingHistory.length,
            riskBaselines: this.riskBaselines.size,
            complianceBaselines: this.complianceBaselines.size,
            patternHistorySize: this.patternHistory.length,
            config: this.config,
        };
    }
    resetBaselines() {
        this.riskBaselines.clear();
        this.complianceBaselines.clear();
        this.patternHistory = [];
    }
}
exports.AnomalyDetectionService = AnomalyDetectionService;
//# sourceMappingURL=anomaly-detection.js.map