import { UnifiedFinding } from '../core/unified-finding-schema';
export interface CICDGateConfig {
    enabled: boolean;
    severityThreshold: 'critical' | 'high' | 'medium' | 'low';
    failOnThreshold: boolean;
    maxFindings?: number;
    allowedFindings?: string[];
}
export interface PreCommitHookResult {
    passed: boolean;
    findings: UnifiedFinding[];
    blockedFiles?: string[];
    message: string;
}
export interface PRSecurityCheckResult {
    passed: boolean;
    findings: UnifiedFinding[];
    newFindings: UnifiedFinding[];
    resolvedFindings: UnifiedFinding[];
    riskScore: number;
    message: string;
    blocking: boolean;
}
export interface BuildSecurityGateResult {
    passed: boolean;
    findings: UnifiedFinding[];
    riskScore: number;
    blocking: boolean;
    message: string;
}
export interface DeploymentSecurityGateResult {
    passed: boolean;
    findings: UnifiedFinding[];
    riskScore: number;
    blocking: boolean;
    message: string;
    deploymentBlocked: boolean;
}
export declare class CICDIntegration {
    runPreCommitHook(stagedFiles: string[], findings: UnifiedFinding[], config: CICDGateConfig): Promise<PreCommitHookResult>;
    runPRSecurityCheck(baseFindings: UnifiedFinding[], headFindings: UnifiedFinding[], config: CICDGateConfig): Promise<PRSecurityCheckResult>;
    runBuildSecurityGate(findings: UnifiedFinding[], config: CICDGateConfig): Promise<BuildSecurityGateResult>;
    runDeploymentSecurityGate(findings: UnifiedFinding[], environment: string, config: CICDGateConfig): Promise<DeploymentSecurityGateResult>;
    private calculateRiskScore;
    generateGitHubActionsWorkflow(config: CICDGateConfig): string;
    generateGitLabCIConfig(config: CICDGateConfig): string;
    generateJenkinsfile(config: CICDGateConfig): string;
}
