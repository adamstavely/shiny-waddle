import { UnifiedFinding } from '../core/unified-finding-schema';
export interface CorrelationConfig {
    enabled: boolean;
    crossScannerDeduplication: {
        enabled: boolean;
        similarityThreshold: number;
        strategies: ('cve' | 'cwe' | 'location' | 'semantic' | 'asset')[];
    };
    relatedFindingGrouping: {
        enabled: boolean;
        maxDistance: number;
        groupingStrategies: ('cwe-chain' | 'asset-chain' | 'dependency-chain' | 'attack-path')[];
    };
    rootCauseAnalysis: {
        enabled: boolean;
        maxDepth: number;
    };
    impactAnalysis: {
        enabled: boolean;
        considerAssetCriticality: boolean;
        considerBusinessImpact: boolean;
    };
}
export interface RelatedFindingGroup {
    id: string;
    primaryFinding: string;
    findings: string[];
    relationshipType: 'duplicate' | 'related' | 'chain' | 'cluster';
    confidence: number;
    rootCause?: string;
    impactScore: number;
    createdAt: Date;
}
export interface RootCauseAnalysis {
    findingId: string;
    rootCause?: string;
    chain: string[];
    depth: number;
    confidence: number;
    analysis: {
        type: 'dependency' | 'configuration' | 'code' | 'infrastructure' | 'unknown';
        description: string;
        evidence: string[];
    };
}
export interface ImpactAnalysis {
    findingId: string;
    directImpact: {
        affectedAssets: string[];
        affectedApplications: string[];
        severity: 'critical' | 'high' | 'medium' | 'low';
        businessImpact: number;
    };
    cascadingImpact: {
        relatedFindings: string[];
        potentialExploits: string[];
        complianceImpact: string[];
        estimatedRemediationCost: number;
    };
    overallImpactScore: number;
}
export interface CorrelationResult {
    findings: UnifiedFinding[];
    groups: RelatedFindingGroup[];
    rootCauses: Map<string, RootCauseAnalysis>;
    impacts: Map<string, ImpactAnalysis>;
    duplicates: Map<string, string>;
    statistics: {
        totalFindings: number;
        uniqueFindings: number;
        duplicateCount: number;
        groupCount: number;
        averageGroupSize: number;
    };
}
export declare class FindingCorrelationEngine {
    private config;
    private findingsIndex;
    private assetIndex;
    private cveIndex;
    private cweIndex;
    constructor(config?: Partial<CorrelationConfig>);
    correlate(findings: UnifiedFinding[]): Promise<CorrelationResult>;
    private buildIndices;
    private crossScannerDeduplication;
    private calculateSimilarity;
    private selectPrimaryFinding;
    private mergeFindingMetadata;
    private groupRelatedFindings;
    private groupByCWEChain;
    private groupByAssetChain;
    private groupByDependencyChain;
    private groupByAttackPath;
    private analyzeRootCause;
    private determineRootCauseType;
    private findRelatedFindings;
    private analyzeImpact;
    private estimateBusinessImpact;
    private identifyPotentialExploits;
    private estimateRemediationCost;
    private calculateOverallImpactScore;
    private calculateGroupImpactScore;
    private enrichFindingsWithCorrelation;
    private getAssetKey;
    private getLocationKey;
    private locationSimilarity;
}
