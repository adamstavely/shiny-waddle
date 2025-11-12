import { ABACPolicy, Resource, PolicyConflict, PolicyCoverage, PolicySimulation } from '../core/types';
import { PolicyDecisionPoint } from './policy-decision-point';
import { PolicyTestCase } from './policy-as-code';
export interface PolicyValidationTesterConfig {
    pdp: PolicyDecisionPoint;
    conflictDetection?: {
        checkPriority?: boolean;
        checkOverlap?: boolean;
        checkContradiction?: boolean;
    };
    coverageAnalysis?: {
        minCoverage?: number;
        generateRecommendations?: boolean;
    };
    performanceTesting?: {
        iterations?: number;
        maxLatency?: number;
    };
}
export declare class PolicyValidationTester {
    private pdp;
    private config;
    constructor(config: PolicyValidationTesterConfig | PolicyDecisionPoint);
    detectPolicyConflicts(policies: ABACPolicy[]): Promise<PolicyConflict[]>;
    analyzePolicyCoverage(resources: Resource[], policies: ABACPolicy[]): Promise<PolicyCoverage>;
    testPolicyPerformance(policy: ABACPolicy, iterations?: number): Promise<{
        policyId: string;
        evaluationCount: number;
        totalTime: number;
        averageTime: number;
        minTime: number;
        maxTime: number;
        p50: number;
        p95: number;
        p99: number;
    }>;
    runRegressionTests(baselinePolicies: ABACPolicy[], currentPolicies: ABACPolicy[], testCases: PolicyTestCase[]): Promise<{
        policyId: string;
        baselineResults: Map<string, boolean>;
        currentResults: Map<string, boolean>;
        regressions: Array<{
            testCase: string;
            baselineResult: boolean;
            currentResult: boolean;
        }>;
    }>;
    simulatePolicyChange(policy: ABACPolicy, testCases: PolicyTestCase[]): Promise<PolicySimulation>;
    private detectOverlap;
    private conditionsOverlap;
    private findApplicablePolicies;
    private evaluateCondition;
    private generateRecommendedPolicy;
    private generateTestRequest;
}
