import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
export declare class SecurityHeadersTestSuite extends BaseTestSuite {
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testCORSConfiguration(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testCSP(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testHSTS(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testXContentTypeOptions(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testXFrameOptions(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testXSSProtection(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testReferrerPolicy(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testPermissionsPolicy(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testServerInformationDisclosure(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
