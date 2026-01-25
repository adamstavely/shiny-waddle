import { TestResult, NetworkSegment, FirewallRule } from '../core/types';
import { ServiceMeshConfig } from './service-mesh-integration';
export interface NetworkConnectivityProvider {
    testConnectivity(source: string, target: string, protocol: string, port: number): Promise<{
        allowed: boolean;
        policyApplied?: string;
        latency?: number;
    }>;
    validateSegmentation(segments: NetworkSegment[]): Promise<{
        validated: boolean;
        violations: Array<{
            source: string;
            target: string;
            reason: string;
        }>;
    }>;
}
export interface NetworkMicrosegmentationTesterConfig {
    serviceMeshConfig?: ServiceMeshConfig;
    connectivityProvider?: NetworkConnectivityProvider;
    mockData?: {
        connectivityAllowed?: boolean;
        segmentationValidated?: boolean;
        segmentationViolations?: Array<{
            source: string;
            target: string;
            reason: string;
        }>;
    };
}
export declare class NetworkMicrosegmentationTester {
    private serviceMesh?;
    private config;
    private connectivityProvider?;
    constructor(config?: NetworkMicrosegmentationTesterConfig | ServiceMeshConfig);
    testFirewallRules(rules: FirewallRule[]): Promise<TestResult[]>;
    testServiceToServiceTraffic(source: string, target: string): Promise<TestResult>;
    validateNetworkSegmentation(segments: NetworkSegment[]): Promise<TestResult[]>;
    testServiceMeshPolicies(meshConfig: ServiceMeshConfig): Promise<TestResult[]>;
}
