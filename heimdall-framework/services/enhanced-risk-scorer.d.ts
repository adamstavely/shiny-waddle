import { UnifiedFinding } from '../core/unified-finding-schema';
export interface EnhancedRiskScore {
    findingId: string;
    baseScore: number;
    adjustedScore: number;
    factors: {
        severity: number;
        exploitability: number;
        assetCriticality: number;
        exposure: number;
        dataSensitivity: number;
        complianceImpact: number;
        businessImpact: number;
        remediationComplexity: number;
    };
    age: number;
    trend: 'increasing' | 'stable' | 'decreasing';
    threatIntelligence?: {
        activeExploits: boolean;
        exploitInWild: boolean;
        ransomware: boolean;
        threatActorInterest: 'high' | 'medium' | 'low';
    };
    priority: number;
    priorityReason: string;
    calculatedAt: Date;
    version: string;
}
export interface RiskAggregation {
    level: 'application' | 'team' | 'organization';
    identifier: string;
    totalFindings: number;
    riskScore: number;
    averageRiskScore: number;
    maxRiskScore: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    trend: {
        current: number;
        previous: number;
        change: number;
        direction: 'increasing' | 'stable' | 'decreasing';
    };
    bySeverity: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    topRisks: Array<{
        findingId: string;
        riskScore: number;
        title: string;
    }>;
}
export interface PrioritizationConfig {
    weights: {
        severity: number;
        exploitability: number;
        assetCriticality: number;
        exposure: number;
        dataSensitivity: number;
        complianceImpact: number;
        businessImpact: number;
        remediationComplexity: number;
        age: number;
        threatIntelligence: number;
    };
    slaThresholds: {
        critical: number;
        high: number;
        medium: number;
        low: number;
    };
    mlConfig?: {
        enabled: boolean;
        modelVersion?: string;
        confidenceThreshold?: number;
    };
}
export interface AssetCriticalityConfig {
    applications: Record<string, 'critical' | 'high' | 'medium' | 'low'>;
    componentPatterns: Array<{
        pattern: RegExp;
        criticality: 'critical' | 'high' | 'medium' | 'low';
    }>;
    defaultByType: Record<string, 'critical' | 'high' | 'medium' | 'low'>;
}
export declare class EnhancedRiskScorer {
    private config;
    private assetCriticality;
    private historicalScores;
    constructor(config?: Partial<PrioritizationConfig>, assetCriticality?: Partial<AssetCriticalityConfig>);
    calculateRiskScore(finding: UnifiedFinding): EnhancedRiskScore;
    calculateRiskScores(findings: UnifiedFinding[]): EnhancedRiskScore[];
    prioritizeFindings(findings: UnifiedFinding[], riskScores?: EnhancedRiskScore[]): Array<{
        finding: UnifiedFinding;
        riskScore: EnhancedRiskScore;
    }>;
    aggregateByApplication(findings: UnifiedFinding[], applicationId: string): RiskAggregation;
    aggregateByTeam(findings: UnifiedFinding[], teamName: string, getApplicationsByTeam: (team: string) => Promise<Array<{
        id: string;
    }>>): Promise<RiskAggregation>;
    aggregateByOrganization(findings: UnifiedFinding[]): RiskAggregation;
    getRiskTrends(findings: UnifiedFinding[], periodDays?: number): Array<{
        date: Date;
        riskScore: number;
        count: number;
    }>;
    private extractBaseScore;
    private calculateFactors;
    private calculateSeverityFactor;
    private calculateExploitabilityFactor;
    private calculateAssetCriticalityFactor;
    private calculateExposureFactor;
    private calculateDataSensitivityFactor;
    private calculateComplianceImpactFactor;
    private calculateBusinessImpactFactor;
    private calculateRemediationComplexityFactor;
    private calculateAge;
    private calculateTrend;
    private assessThreatIntelligence;
    private adjustScore;
    private calculatePriority;
    private aggregateRisks;
    private calculateAggregatedRiskScore;
    private storeHistoricalScore;
    updateAssetCriticality(config: Partial<AssetCriticalityConfig>): void;
    updateConfig(config: Partial<PrioritizationConfig>): void;
}
