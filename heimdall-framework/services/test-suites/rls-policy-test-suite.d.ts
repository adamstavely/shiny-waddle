import { BaseTestSuite } from './base-test-suite';
import { APISecurityTest, APISecurityTestResult } from '../api-security-tester';
import { DatabaseConfig } from '../../core/types';
export declare class RLSPolicyTestSuite extends BaseTestSuite {
    private rlsTester;
    private databaseConfig?;
    constructor(config: any, databaseConfig?: DatabaseConfig);
    runAllTests(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult[]>;
    testRLSCoverage(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
    testCrossTenantIsolation(endpoint: string, method: string, test?: Partial<APISecurityTest>): Promise<APISecurityTestResult>;
}
