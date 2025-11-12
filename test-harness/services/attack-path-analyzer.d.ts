import { UnifiedFinding } from '../core/unified-finding-schema';
export interface AttackPathConfig {
    enabled: boolean;
    maxPathDepth: number;
    includeTransitivePaths: boolean;
    prioritizeByExploitability: boolean;
    prioritizeByAssetCriticality: boolean;
    framework: 'mitre-attack' | 'owasp' | 'custom';
}
export interface AttackStep {
    findingId: string;
    vulnerability: {
        cve?: string;
        cwe?: string;
        title: string;
        severity: string;
    };
    asset: {
        type: string;
        component?: string;
        applicationId?: string;
    };
    technique?: {
        id: string;
        name: string;
        framework: string;
    };
    exploitability: 'high' | 'medium' | 'low';
    prerequisites: string[];
    impact: {
        dataAccess: boolean;
        privilegeEscalation: boolean;
        lateralMovement: boolean;
        persistence: boolean;
    };
}
export interface AttackPath {
    id: string;
    name: string;
    steps: AttackStep[];
    severity: 'critical' | 'high' | 'medium' | 'low';
    exploitability: 'high' | 'medium' | 'low';
    impact: {
        overall: number;
        dataAccess: boolean;
        privilegeEscalation: boolean;
        lateralMovement: boolean;
        persistence: boolean;
        businessImpact: number;
    };
    criticality: number;
    estimatedTimeToExploit: number;
    remediationPriority: number;
    description: string;
    evidence: string[];
    createdAt: Date;
}
export interface AttackSurface {
    applicationId?: string;
    assetType: string;
    entryPoints: AttackStep[];
    paths: AttackPath[];
    criticalPaths: AttackPath[];
    totalVulnerabilities: number;
    exploitableVulnerabilities: number;
    riskScore: number;
    coverage: {
        mitreTactics: string[];
        owaspCategories: string[];
    };
}
export interface AttackPathAnalysis {
    findings: UnifiedFinding[];
    paths: AttackPath[];
    criticalPaths: AttackPath[];
    attackSurfaces: Map<string, AttackSurface>;
    statistics: {
        totalPaths: number;
        criticalPathsCount: number;
        averagePathLength: number;
        mostCommonTechnique: string;
        highestRiskPath: string;
    };
    prioritization: Map<string, number>;
}
export declare class AttackPathAnalyzer {
    private config;
    private mitreTechniques;
    private cweToMitreMapping;
    private attackChains;
    constructor(config?: Partial<AttackPathConfig>);
    analyze(findings: UnifiedFinding[]): Promise<AttackPathAnalysis>;
    private mapFindingsToAttackSteps;
    private mapCWEToMitreTechniques;
    private assessExploitability;
    private assessImpact;
    private findPrerequisites;
    private buildAttackPaths;
    private buildPathsFromStep;
    private canReachStep;
    private buildTransitivePaths;
    private createAttackPath;
    private identifyCriticalPaths;
    private buildAttackSurfaces;
    private prioritizeFindings;
    private calculateStatistics;
    private calculatePathCriticality;
    private estimateTimeToExploit;
    private calculateRemediationPriority;
    private estimateBusinessImpact;
    private generatePathDescription;
    private generatePathName;
    private deduplicatePaths;
    private calculateAttackSurfaceRiskScore;
    private initializeAttackFramework;
}
