import { UnifiedFinding } from '../core/unified-finding-schema';
import { EventEmitter } from 'events';
export interface Anomaly {
    id: string;
    type: 'unusual_pattern' | 'risk_spike' | 'compliance_drift' | 'attack_pattern';
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    detectedAt: Date;
    findings: UnifiedFinding[];
    metrics: Record<string, any>;
    confidence: number;
    metadata?: Record<string, any>;
}
export interface AnomalyDetectionConfig {
    enableUnusualPatterns: boolean;
    enableRiskSpikeDetection: boolean;
    enableComplianceDriftDetection: boolean;
    enableAttackPatternDetection: boolean;
    riskSpikeThreshold?: number;
    complianceDriftThreshold?: number;
    timeWindow?: number;
    minFindingsForPattern?: number;
}
export interface FindingPattern {
    scannerId: string;
    severity: string;
    applicationId?: string;
    component?: string;
    count: number;
    trend: 'increasing' | 'decreasing' | 'stable';
    changeRate: number;
}
export interface RiskSpike {
    applicationId?: string;
    baselineRisk: number;
    currentRisk: number;
    increase: number;
    findings: UnifiedFinding[];
    timeWindow: {
        start: Date;
        end: Date;
    };
}
export interface ComplianceDrift {
    framework: string;
    controlId?: string;
    baselineCompliance: number;
    currentCompliance: number;
    decrease: number;
    findings: UnifiedFinding[];
    timeWindow: {
        start: Date;
        end: Date;
    };
}
export interface AttackPattern {
    pattern: string;
    indicators: string[];
    findings: UnifiedFinding[];
    confidence: number;
    detectedAt: Date;
}
export declare class AnomalyDetectionService extends EventEmitter {
    private config;
    private findingHistory;
    private riskBaselines;
    private complianceBaselines;
    private patternHistory;
    private maxHistorySize;
    constructor(config?: Partial<AnomalyDetectionConfig>);
    analyzeFindings(findings: UnifiedFinding[]): Promise<Anomaly[]>;
    private detectUnusualPatterns;
    private detectRiskSpikes;
    private detectComplianceDrift;
    private detectAttackPatterns;
    private mapChangeRateToSeverity;
    private mapRiskIncreaseToSeverity;
    private mapComplianceDecreaseToSeverity;
    getStats(): {
        historySize: number;
        riskBaselines: number;
        complianceBaselines: number;
        patternHistorySize: number;
        config: AnomalyDetectionConfig;
    };
    resetBaselines(): void;
}
