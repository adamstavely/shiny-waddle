import { Contract, ContractTestConfig } from '../core/types';
export interface ContractTestResult {
    compliant: boolean;
    contractName: string;
    dataOwner: string;
    requirementResults: RequirementTestResult[];
    violations: string[];
}
export interface RequirementTestResult {
    requirementId: string;
    description: string;
    passed: boolean;
    violation?: string;
}
export declare class ContractTester {
    private config;
    private queryAnalyzer;
    constructor(config: ContractTestConfig);
    testContract(contract: Contract): Promise<ContractTestResult>;
    private testRequirement;
    private testFieldRestriction;
    private testAggregationRequirement;
    private testJoinRestriction;
    private testExportRestriction;
    generateTestsFromContract(contract: Contract): Promise<any[]>;
    private generateTestFromRequirement;
}
