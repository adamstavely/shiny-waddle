"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RiskScorer = void 0;
class RiskScorer {
    constructor(config) {
        this.config = {
            weights: {
                testType: {
                    'access-control': 30,
                    'data-behavior': 25,
                    'contract': 20,
                    'dataset-health': 15,
                },
                dataSensitivity: {
                    'restricted': 40,
                    'confidential': 30,
                    'internal': 20,
                    'public': 10,
                },
                userRole: {
                    'admin': 10,
                    'researcher': 20,
                    'analyst': 25,
                    'viewer': 30,
                },
                violationType: {
                    'sql-injection': 50,
                    'privilege-escalation': 45,
                    'data-leakage': 40,
                    'pii-exposure': 35,
                    'over-broad-query': 30,
                    'missing-filter': 25,
                    'disallowed-join': 20,
                    'policy-violation': 15,
                },
            },
            thresholds: {
                critical: 80,
                high: 60,
                medium: 40,
            },
            ...config,
        };
    }
    scoreTestResult(result) {
        if (result.passed) {
            return {
                testResult: result,
                riskScore: 0,
                severity: 'low',
                businessImpact: 0,
                priority: 0,
                factors: [],
                recommendations: [],
            };
        }
        const factors = this.identifyRiskFactors(result);
        const riskScore = this.calculateRiskScore(result, factors);
        const severity = this.determineSeverity(riskScore);
        const businessImpact = this.calculateBusinessImpact(result, factors);
        const priority = this.calculatePriority(riskScore, businessImpact);
        const recommendations = this.generateRecommendations(result, factors);
        return {
            testResult: result,
            riskScore,
            severity,
            businessImpact,
            priority,
            factors,
            recommendations,
        };
    }
    scoreTestResults(results) {
        return results.map(result => this.scoreTestResult(result));
    }
    prioritizeRisks(scores) {
        return [...scores].sort((a, b) => {
            if (b.priority !== a.priority) {
                return b.priority - a.priority;
            }
            if (b.riskScore !== a.riskScore) {
                return b.riskScore - a.riskScore;
            }
            const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
            return severityOrder[b.severity] - severityOrder[a.severity];
        });
    }
    identifyRiskFactors(result) {
        const factors = [];
        const testTypeWeight = this.config.weights.testType[result.testType] || 10;
        factors.push({
            name: 'Test Type',
            impact: testTypeWeight,
            description: `${result.testType} test failure`,
        });
        const sensitivity = result.details?.resource?.sensitivity ||
            result.details?.sensitivity || 'internal';
        const sensitivityWeight = this.config.weights.dataSensitivity[sensitivity] || 20;
        factors.push({
            name: 'Data Sensitivity',
            impact: sensitivityWeight,
            description: `Accessing ${sensitivity} data`,
        });
        const userRole = result.details?.user?.role || 'unknown';
        const roleWeight = this.config.weights.userRole[userRole] || 15;
        factors.push({
            name: 'User Role',
            impact: roleWeight,
            description: `Violation by ${userRole} role`,
        });
        const violationType = this.identifyViolationType(result);
        if (violationType) {
            const violationWeight = this.config.weights.violationType[violationType] || 20;
            factors.push({
                name: 'Violation Type',
                impact: violationWeight,
                description: `${violationType} violation`,
            });
        }
        if (result.error) {
            factors.push({
                name: 'Error Severity',
                impact: 30,
                description: `Error: ${result.error}`,
            });
        }
        return factors;
    }
    calculateRiskScore(result, factors) {
        let score = 0;
        for (const factor of factors) {
            score += factor.impact;
        }
        return Math.min(100, score);
    }
    determineSeverity(riskScore) {
        if (riskScore >= this.config.thresholds.critical) {
            return 'critical';
        }
        else if (riskScore >= this.config.thresholds.high) {
            return 'high';
        }
        else if (riskScore >= this.config.thresholds.medium) {
            return 'medium';
        }
        else {
            return 'low';
        }
    }
    calculateBusinessImpact(result, factors) {
        let impact = 0;
        const sensitivityFactor = factors.find(f => f.name === 'Data Sensitivity');
        if (sensitivityFactor) {
            impact += sensitivityFactor.impact * 0.4;
        }
        const violationFactor = factors.find(f => f.name === 'Violation Type');
        if (violationFactor) {
            impact += violationFactor.impact * 0.3;
        }
        const testTypeFactor = factors.find(f => f.name === 'Test Type');
        if (testTypeFactor) {
            impact += testTypeFactor.impact * 0.3;
        }
        return Math.min(100, impact);
    }
    calculatePriority(riskScore, businessImpact) {
        return (riskScore * 0.6) + (businessImpact * 0.4);
    }
    identifyViolationType(result) {
        const testName = result.testName.toLowerCase();
        const details = result.details || {};
        if (testName.includes('sql injection') || details.type === 'sql-injection') {
            return 'sql-injection';
        }
        if (testName.includes('privilege') || details.type === 'privilege-escalation') {
            return 'privilege-escalation';
        }
        if (testName.includes('pii') || testName.includes('email') || details.type === 'pii-exposure') {
            return 'pii-exposure';
        }
        if (testName.includes('over-broad') || details.type === 'over-broad-query') {
            return 'over-broad-query';
        }
        if (testName.includes('missing filter') || details.type === 'missing-filter') {
            return 'missing-filter';
        }
        if (testName.includes('join') || details.type === 'disallowed-join') {
            return 'disallowed-join';
        }
        if (details.type === 'data-leakage') {
            return 'data-leakage';
        }
        return 'policy-violation';
    }
    generateRecommendations(result, factors) {
        const recommendations = [];
        const violationType = this.identifyViolationType(result);
        switch (violationType) {
            case 'sql-injection':
                recommendations.push('Use parameterized queries to prevent SQL injection');
                recommendations.push('Implement input validation and sanitization');
                break;
            case 'privilege-escalation':
                recommendations.push('Review and restrict user permissions');
                recommendations.push('Implement principle of least privilege');
                break;
            case 'pii-exposure':
                recommendations.push('Implement PII masking or encryption');
                recommendations.push('Add field-level access controls');
                break;
            case 'over-broad-query':
                recommendations.push('Add required filters to limit data access');
                recommendations.push('Implement query result limits');
                break;
            case 'missing-filter':
                recommendations.push('Enforce required filters in query execution');
                recommendations.push('Add workspace/tenant filtering');
                break;
            case 'disallowed-join':
                recommendations.push('Block disallowed table joins');
                recommendations.push('Review join permissions for user role');
                break;
            default:
                recommendations.push('Review access control policies');
                recommendations.push('Verify policy enforcement');
        }
        const severity = this.determineSeverity(this.calculateRiskScore(result, factors));
        if (severity === 'critical' || severity === 'high') {
            recommendations.push('Immediate remediation required');
            recommendations.push('Consider blocking access until resolved');
        }
        return recommendations;
    }
    getRiskSummary(scores) {
        const bySeverity = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
        };
        let totalRiskScore = 0;
        for (const score of scores) {
            bySeverity[score.severity]++;
            totalRiskScore += score.riskScore;
        }
        return {
            total: scores.length,
            bySeverity,
            averageRiskScore: scores.length > 0 ? totalRiskScore / scores.length : 0,
            criticalCount: bySeverity.critical,
        };
    }
}
exports.RiskScorer = RiskScorer;
//# sourceMappingURL=risk-scorer.js.map