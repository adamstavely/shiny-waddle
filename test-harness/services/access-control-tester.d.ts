import { User, Resource, Context, AccessControlConfig } from '../core/types';
export interface AccessControlTestInput {
    user: User;
    resource: Resource;
    context: Context;
    expectedDecision?: boolean;
}
export interface AccessControlTestResult {
    allowed: boolean;
    expectedAllowed?: boolean;
    decisionReason: string;
    policyRules: string[];
    timestamp: Date;
    latency?: number;
}
export declare class AccessControlTester {
    private config;
    private pdp;
    constructor(config: AccessControlConfig);
    testPDPDecision(input: AccessControlTestInput): Promise<AccessControlTestResult>;
    testAccessScenarios(scenarios: AccessControlTestInput[]): Promise<AccessControlTestResult[]>;
    detectPolicyViolations(user: User, resource: Resource, context: Context): Promise<string[]>;
    validateDecisionConsistency(testCases: AccessControlTestInput[]): Promise<{
        consistent: boolean;
        inconsistencies: string[];
    }>;
}
