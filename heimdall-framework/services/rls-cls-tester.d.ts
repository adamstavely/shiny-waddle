import { TestQuery, User, Resource, TestResult, DatabaseConfig, RLSCoverage, CLSCoverage, DynamicMaskingRule, CrossTenantIsolationTest } from '../core/types';
export interface DatabaseMetadataProvider {
    getTables(database: DatabaseConfig): Promise<string[]>;
    getRLSPolicies(database: DatabaseConfig): Promise<Array<{
        table: string;
        policyName: string;
        policyDefinition: string;
        applicable: boolean;
    }>>;
    getCLSPolicies(database: DatabaseConfig): Promise<Array<{
        table: string;
        column: string;
        policyType: 'masking' | 'encryption' | 'redaction';
        policyDefinition: string;
        applicable: boolean;
    }>>;
}
export interface RLSCLSTesterConfig {
    metadataProvider?: DatabaseMetadataProvider;
    mockData?: {
        tables?: string[];
        rlsPolicies?: Array<{
            table: string;
            policyName: string;
            policyDefinition: string;
            applicable: boolean;
        }>;
        clsPolicies?: Array<{
            table: string;
            column: string;
            policyType: 'masking' | 'encryption' | 'redaction';
            policyDefinition: string;
            applicable: boolean;
        }>;
    };
    testLogic?: {
        skipDisabledPolicies?: boolean;
        validateCrossTenant?: boolean;
    };
}
export declare class RLSCLSTester {
    private analyzer;
    private config;
    private metadataProvider?;
    constructor(config?: RLSCLSTesterConfig);
    testRLSCoverage(database: DatabaseConfig): Promise<RLSCoverage>;
    testCLSCoverage(database: DatabaseConfig): Promise<CLSCoverage>;
    testDynamicMasking(query: TestQuery, user: User, maskingRules: DynamicMaskingRule[]): Promise<TestResult>;
    testCrossTenantIsolation(tenant1: string, tenant2: string, testQueries: TestQuery[]): Promise<CrossTenantIsolationTest>;
    testPolicyBypassAttempts(user: User, resource: Resource): Promise<TestResult[]>;
    private getDatabaseTables;
    private getRLSPolicies;
    private getCLSPolicies;
    private findApplicableMaskingRules;
    private verifyMaskingApplied;
    private detectCrossTenantAccess;
}
