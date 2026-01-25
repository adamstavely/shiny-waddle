import { TestResult } from '../core/types';
export interface RiskScore {
    testResult: TestResult;
    riskScore: number;
    severity: 'critical' | 'high' | 'medium' | 'low';
    businessImpact: number;
    priority: number;
    factors: RiskFactor[];
    recommendations: string[];
}
export interface RiskFactor {
    name: string;
    impact: number;
    description: string;
}
export interface RiskScoringConfig {
    weights: {
        testType: Record<string, number>;
        dataSensitivity: Record<string, number>;
        userRole: Record<string, number>;
        violationType: Record<string, number>;
    };
    thresholds: {
        critical: number;
        high: number;
        medium: number;
    };
}
export declare class RiskScorer {
    private config;
    constructor(config?: Partial<RiskScoringConfig>);
    scoreTestResult(result: TestResult): RiskScore;
    scoreTestResults(results: TestResult[]): RiskScore[];
    prioritizeRisks(scores: RiskScore[]): RiskScore[];
    private identifyRiskFactors;
    private calculateRiskScore;
    private determineSeverity;
    private calculateBusinessImpact;
    private calculatePriority;
    private identifyViolationType;
    private generateRecommendations;
    getRiskSummary(scores: RiskScore[]): {
        total: number;
        bySeverity: Record<string, number>;
        averageRiskScore: number;
        criticalCount: number;
    };
}
