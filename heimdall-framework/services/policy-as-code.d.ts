import { ABACPolicy } from '../core/types';
import { PolicyVersion } from './policy-versioning';
export interface PolicyAsCodeConfig {
    format: 'json' | 'yaml' | 'rego';
    versioning: boolean;
    testing: {
        enabled: boolean;
        testSuite?: string;
    };
    enforcement: {
        enabled: boolean;
        mode: 'gatekeeper' | 'admission-controller' | 'sidecar' | 'inline';
    };
}
export interface PolicyTestResult {
    policyId: string;
    passed: boolean;
    testCases: PolicyTestCase[];
    errors: string[];
    warnings: string[];
}
export interface PolicyTestCase {
    name: string;
    description?: string;
    request: {
        subject: any;
        resource: any;
        action: string;
        context?: any;
    };
    expected: {
        allowed: boolean;
        reason?: string;
    };
    actual?: {
        allowed: boolean;
        reason?: string;
    };
    passed: boolean;
}
export interface PolicyEnforcementResult {
    policyId: string;
    enforced: boolean;
    enforcementPoint: string;
    mode: string;
    timestamp: Date;
    errors?: string[];
}
export declare class PolicyAsCode {
    private versioning;
    private policiesDir;
    private config;
    constructor(policiesDir?: string, config?: Partial<PolicyAsCodeConfig>);
    loadPolicy(filePath: string): Promise<{
        policies: ABACPolicy[];
        format: 'json' | 'yaml' | 'rego';
        metadata?: any;
    }>;
    private loadYAMLPolicy;
    private loadJSONPolicy;
    private loadRegoPolicy;
    private normalizePolicy;
    savePolicy(policies: ABACPolicy[], filePath: string, format?: 'json' | 'yaml'): Promise<void>;
    testPolicy(policy: ABACPolicy, testCases: PolicyTestCase[], evaluator: (request: any) => Promise<{
        allowed: boolean;
        reason?: string;
    }>): Promise<PolicyTestResult>;
    enforcePolicy(policy: ABACPolicy, enforcementPoint: string): Promise<PolicyEnforcementResult>;
    private deployToEnforcementPoint;
    private deployAsGatekeeperPolicy;
    private deployAsAdmissionController;
    private deployAsSidecar;
    convertPolicy(policy: ABACPolicy, targetFormat: 'json' | 'yaml' | 'rego'): Promise<string>;
    validatePolicy(policy: ABACPolicy | string, format?: 'json' | 'yaml' | 'rego'): Promise<{
        valid: boolean;
        errors: string[];
    }>;
    getVersionHistory(limit?: number): Promise<PolicyVersion[]>;
    rollbackToVersion(version: string): Promise<PolicyVersion>;
}
