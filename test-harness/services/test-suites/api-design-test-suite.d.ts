import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
export declare class APIDesignTestSuite extends BaseTestSuite {
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testHTTPMethodValidation(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testContentTypeValidation(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testEndpointEnumeration(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testVerboseErrors(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testMissingSecurityControls(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testAPIVersioningSecurity(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
