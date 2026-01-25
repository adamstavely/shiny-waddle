import { User, TestResult, OktaPolicyTest, AzureADConditionalAccessPolicy, GCPIAMBinding } from '../core/types';
export interface IdentityProviderIntegration {
    checkADGroupMembership(userId: string, group: string): Promise<boolean>;
    comparePolicies(source: {
        type: string;
        config: any;
    }, target: {
        type: string;
        config: any;
    }): Promise<{
        synchronized: boolean;
        differences: Array<{
            policyId: string;
            sourceValue: any;
            targetValue: any;
            field: string;
        }>;
    }>;
}
export interface IdentityProviderTesterConfig {
    providerIntegration?: IdentityProviderIntegration;
    mockData?: {
        adGroupMembership?: boolean;
        policySynchronized?: boolean;
        policyDifferences?: Array<{
            policyId: string;
            sourceValue: any;
            targetValue: any;
            field: string;
        }>;
    };
}
export declare class IdentityProviderTester {
    private config;
    private providerIntegration?;
    constructor(config?: IdentityProviderTesterConfig);
    testADGroupMembership(user: User, group: string): Promise<TestResult>;
    testOktaPolicySync(policy: OktaPolicyTest): Promise<TestResult>;
    testAuth0PolicySync(policy: any): Promise<TestResult>;
    testAzureADConditionalAccess(policy: AzureADConditionalAccessPolicy): Promise<TestResult>;
    testGCPIAMBindings(binding: GCPIAMBinding): Promise<TestResult>;
    validatePolicySynchronization(source: {
        type: string;
        config: any;
    }, target: {
        type: string;
        config: any;
    }): Promise<TestResult>;
}
