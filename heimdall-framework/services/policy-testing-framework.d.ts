import { ABACPolicy } from '../core/types';
import { PolicyTestCase, PolicyTestResult } from './policy-as-code';
import { PolicyDecisionPoint } from './policy-decision-point';
export interface PolicyTestSuite {
    id: string;
    name: string;
    description?: string;
    policies: ABACPolicy[];
    testCases: PolicyTestCase[];
    createdAt: Date;
    updatedAt: Date;
}
export interface PolicyRegressionTest {
    policyId: string;
    baselineResults: Map<string, boolean>;
    currentResults: Map<string, boolean>;
    regressions: Array<{
        testCase: string;
        baselineResult: boolean;
        currentResult: boolean;
    }>;
}
export interface PolicyPerformanceMetrics {
    policyId: string;
    evaluationCount: number;
    totalTime: number;
    averageTime: number;
    minTime: number;
    maxTime: number;
    p50: number;
    p95: number;
    p99: number;
}
export declare class PolicyTestingFramework {
    private pdp;
    constructor(pdp: PolicyDecisionPoint);
    runUnitTests(policy: ABACPolicy, testCases: PolicyTestCase[]): Promise<PolicyTestResult>;
    runRegressionTests(policy: ABACPolicy, baselineResults: Map<string, boolean>, testCases: PolicyTestCase[]): Promise<PolicyRegressionTest>;
    runPerformanceTests(policy: ABACPolicy, testCase: PolicyTestCase, iterations?: number): Promise<PolicyPerformanceMetrics>;
    generateTestCases(policy: ABACPolicy): PolicyTestCase[];
    private generateSubjectFromCondition;
    private generateResourceFromCondition;
    createTestSuite(name: string, policies: ABACPolicy[], testCases: PolicyTestCase[]): PolicyTestSuite;
    runTestSuite(suite: PolicyTestSuite): Promise<{
        suiteId: string;
        results: PolicyTestResult[];
        summary: {
            total: number;
            passed: number;
            failed: number;
            passRate: number;
        };
    }>;
}
