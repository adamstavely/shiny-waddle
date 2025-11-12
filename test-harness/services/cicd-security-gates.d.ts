import { SecurityGateConfig, SecurityGateResult, PullRequest } from '../core/types';
import { IACScanner } from './iac-scanner';
import { ContainerSecurityScanner } from './container-security-scanner';
import { K8sRBACValidator } from './k8s-rbac-validator';
import { PolicyValidationTester } from './policy-validation-tester';
import { ABACPolicy } from '../core/types';
export interface CICDSecurityGatesConfig {
    iacScanner?: IACScanner;
    containerScanner?: ContainerSecurityScanner;
    k8sValidator?: K8sRBACValidator;
    policyValidator?: PolicyValidationTester;
    filePatterns?: {
        iac?: string[];
        container?: string[];
        k8s?: string[];
    };
    severityWeights?: {
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
    };
    imageExtractor?: (files: string[]) => string[];
}
export declare class CICDSecurityGates {
    private iacScanner;
    private containerScanner;
    private k8sValidator;
    private policyValidator?;
    private config;
    constructor(config?: CICDSecurityGatesConfig | IACScanner, containerScanner?: ContainerSecurityScanner, k8sValidator?: K8sRBACValidator, policyValidator?: PolicyValidationTester);
    validatePreMergePolicies(pr: PullRequest, policies: ABACPolicy[]): Promise<SecurityGateResult>;
    checkSecurityGates(pr: PullRequest, config: SecurityGateConfig): Promise<SecurityGateResult>;
    private calculateRiskScore;
    private severityLevel;
}
