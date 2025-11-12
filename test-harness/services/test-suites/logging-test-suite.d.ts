import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
export declare class LoggingTestSuite extends BaseTestSuite {
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testAuditLogging(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testLogInjection(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testSensitiveDataInLogs(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testMonitoringCoverage(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
