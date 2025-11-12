import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
export declare class AuthorizationTestSuite extends BaseTestSuite {
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testHorizontalPrivilegeEscalation(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testVerticalPrivilegeEscalation(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testBOLA(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testMassAssignment(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testFunctionLevelAuthorization(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testRBAC(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testABAC(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
