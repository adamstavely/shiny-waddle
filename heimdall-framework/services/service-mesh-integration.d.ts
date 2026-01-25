import { User } from '../core/types';
export interface ServiceMeshConfig {
    type: 'istio' | 'envoy' | 'linkerd';
    controlPlaneEndpoint: string;
    namespace?: string;
    credentials?: {
        token?: string;
        certificate?: string;
    };
}
export interface ServiceMeshPolicy {
    name: string;
    namespace: string;
    type: 'AuthorizationPolicy' | 'PeerAuthentication' | 'RequestAuthentication';
    spec: any;
}
export interface ServiceToServiceTest {
    sourceService: string;
    targetService: string;
    path: string;
    method: string;
    expectedAllowed: boolean;
}
export interface ServiceMeshTestResult {
    test: ServiceToServiceTest;
    allowed: boolean;
    policyApplied?: string;
    error?: string;
}
export declare class ServiceMeshIntegration {
    private config;
    constructor(config: ServiceMeshConfig);
    testServiceToServiceAccess(test: ServiceToServiceTest): Promise<ServiceMeshTestResult>;
    private testIstioAccess;
    private testEnvoyAccess;
    private getEnvoyRBACConfig;
    private evaluateEnvoyRBAC;
    private matchesEnvoyPrincipals;
    private matchesEnvoyPermissions;
    private getIstioPolicy;
    private getIstioPolicyFromFile;
    private evaluateIstioPolicy;
    private matchesIstioRule;
    createIstioPolicy(policy: ServiceMeshPolicy): Promise<ServiceMeshPolicy>;
    private saveIstioPolicyToFile;
    testMicroservicesAccess(services: string[], user: User): Promise<ServiceMeshTestResult[]>;
    validatePolicies(policies: ServiceMeshPolicy[]): Promise<{
        valid: boolean;
        errors: string[];
    }>;
    private validateAuthorizationPolicy;
    getServiceMeshMetrics(): Promise<{
        totalPolicies: number;
        services: number;
        requests: number;
        deniedRequests: number;
    }>;
    private getIstioMetrics;
    private getEnvoyMetrics;
}
