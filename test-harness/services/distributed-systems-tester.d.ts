import { User, Resource } from '../core/types';
import { TestResult } from '../core/types';
import { PolicyDecisionPoint } from './policy-decision-point';
export interface DistributedSystemConfig {
    regions: RegionConfig[];
    coordination?: {
        type: 'consul' | 'etcd' | 'zookeeper' | 'custom';
        endpoint?: string;
    };
    policySync?: {
        enabled: boolean;
        syncInterval?: number;
        consistencyLevel?: 'strong' | 'eventual' | 'weak';
    };
}
export interface RegionConfig {
    id: string;
    name: string;
    endpoint: string;
    pdpEndpoint?: string;
    timezone?: string;
    latency?: number;
    credentials?: Record<string, string>;
}
export interface DistributedTest {
    name: string;
    testType: 'policy-consistency' | 'multi-region' | 'synchronization' | 'transaction' | 'eventual-consistency';
    user?: User;
    resource?: Resource;
    action?: string;
    expectedResult?: boolean;
    regions?: string[];
    timeout?: number;
}
export interface DistributedTestResult extends TestResult {
    testName: string;
    distributedTestType: string;
    regionResults: RegionTestResult[];
    consistencyCheck: {
        consistent: boolean;
        inconsistencies: Inconsistency[];
    };
    synchronizationCheck?: {
        synchronized: boolean;
        syncTime?: number;
        regionsOutOfSync?: string[];
    };
    performanceMetrics?: {
        totalTime: number;
        averageLatency: number;
        slowestRegion: string;
        fastestRegion: string;
    };
}
export interface RegionTestResult {
    regionId: string;
    regionName: string;
    allowed: boolean;
    decision: any;
    latency: number;
    timestamp: Date;
    error?: string;
}
export interface Inconsistency {
    region1: string;
    region2: string;
    difference: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
}
export declare class DistributedSystemsTester {
    private config;
    private pdp?;
    constructor(config: DistributedSystemConfig, pdp?: PolicyDecisionPoint);
    testPolicyConsistency(test: DistributedTest): Promise<DistributedTestResult>;
    testMultiRegion(test: DistributedTest): Promise<DistributedTestResult>;
    testPolicySynchronization(test: DistributedTest): Promise<DistributedTestResult>;
    testDistributedTransaction(test: DistributedTest): Promise<DistributedTestResult>;
    testEventualConsistency(test: DistributedTest): Promise<DistributedTestResult>;
    private testRegion;
    private testRegionAccess;
    private testAllRegions;
    private checkConsistency;
    private checkSynchronization;
    private calculatePerformanceMetrics;
    private updatePolicyInRegion;
    private prepareTransaction;
    private commitTransaction;
    private abortTransaction;
    private getRegionsToTest;
    private sleep;
}
