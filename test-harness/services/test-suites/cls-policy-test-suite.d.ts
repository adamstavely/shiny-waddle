import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { DatabaseConfig } from '../../core/types';
export declare class CLSPolicyTestSuite extends BaseTestSuite {
    private rlsTester;
    private databaseConfig?;
    constructor(config: any, databaseConfig?: DatabaseConfig);
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testCLSCoverage(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testDynamicMasking(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
