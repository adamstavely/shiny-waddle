import { TestResult, APIGatewayPolicy, APIRequest, RateLimitTest, ServiceAuthTest } from '../core/types';
export interface APIGatewayProvider {
    testRateLimit(endpoint: string, requests: number): Promise<{
        blocked: boolean;
        blockedAt?: number;
        actualRequests: number;
    }>;
    testServiceAuth(source: string, target: string): Promise<{
        authenticated: boolean;
        authMethod: 'mtls' | 'jwt' | 'api-key' | 'oauth2';
        certificateValid?: boolean;
        tokenValid?: boolean;
    }>;
    isIPWhitelisted(ip: string): Promise<boolean>;
}
export interface APIGatewayTesterConfig {
    gatewayProvider?: APIGatewayProvider;
    rateLimitConfig?: {
        defaultLimit?: number;
        defaultTimeWindow?: number;
    };
    mockData?: {
        rateLimitBlocked?: boolean;
        serviceAuthResult?: {
            authenticated: boolean;
            authMethod: 'mtls' | 'jwt' | 'api-key' | 'oauth2';
        };
        ipWhitelisted?: boolean;
    };
}
export declare class APIGatewayTester {
    private config;
    private gatewayProvider?;
    constructor(config?: APIGatewayTesterConfig);
    testGatewayPolicy(policy: APIGatewayPolicy, request: APIRequest): Promise<TestResult>;
    testRateLimiting(endpoint: string, requests: number): Promise<RateLimitTest>;
    testAPIVersioning(version: string, endpoint: string): Promise<TestResult>;
    testServiceToServiceAuth(source: string, target: string): Promise<ServiceAuthTest>;
    private evaluateCondition;
}
