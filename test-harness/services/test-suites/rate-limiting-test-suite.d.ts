import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
export declare class RateLimitingTestSuite extends BaseTestSuite {
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testRateLimitEnforcement(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testRateLimitBypass(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testDDoSProtection(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testRequestSizeLimits(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testTimeoutHandling(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testConnectionLimits(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
