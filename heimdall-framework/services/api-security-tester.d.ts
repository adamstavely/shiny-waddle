import { User, Resource } from '../core/types';
import { TestResult } from '../core/types';
export interface APISecurityTestConfig {
    baseUrl: string;
    authentication?: {
        type: 'bearer' | 'basic' | 'oauth2' | 'api-key' | 'jwt';
        credentials: Record<string, string>;
    };
    rateLimitConfig?: {
        maxRequests?: number;
        windowSeconds?: number;
        strategy?: 'fixed' | 'sliding' | 'token-bucket';
    };
    headers?: Record<string, string>;
    timeout?: number;
}
export interface APISecurityTest {
    name: string;
    endpoint: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS';
    expectedStatus?: number;
    expectedAuthRequired?: boolean;
    expectedRateLimit?: boolean;
    body?: any;
    headers?: Record<string, string>;
    user?: User;
    resource?: Resource;
}
export interface APISecurityTestResult extends TestResult {
    testName: string;
    endpoint: string;
    method: string;
    statusCode?: number;
    responseTime?: number;
    rateLimitInfo?: {
        limit?: number;
        remaining?: number;
        resetTime?: Date;
    };
    authenticationResult?: {
        authenticated: boolean;
        tokenValid?: boolean;
        tokenExpired?: boolean;
    };
    authorizationResult?: {
        authorized: boolean;
        reason?: string;
    };
    securityIssues?: string[];
}
export declare class APISecurityTester {
    private config;
    constructor(config: APISecurityTestConfig);
    testRESTAPI(test: APISecurityTest): Promise<APISecurityTestResult>;
    testGraphQLAPI(query: string, variables?: Record<string, any>, test?: APISecurityTest): Promise<APISecurityTestResult>;
    testRateLimiting(endpoint: string, method?: string): Promise<APISecurityTestResult>;
    testInputValidation(endpoint: string, method?: string): Promise<APISecurityTestResult>;
    private buildHeaders;
    private getAuthHeader;
    private extractRateLimitHeaders;
    private detectSecurityIssues;
    private detectGraphQLSecurityIssues;
    private evaluateTestResult;
    runTestSuite(suiteName: string, endpoint: string, method?: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    runFullSecurityScan(endpoint: string, method?: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    runTestByCategory(category: string, endpoint: string, method?: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    getAvailableTestSuites(): string[];
}
