import { TestResult, TestSuite, TestConfiguration } from './types';
export declare class Sentinel {
    private userSimulator;
    private accessControlTester;
    private dataBehaviorTester;
    private contractTester;
    private datasetHealthTester;
    private complianceReporter;
    constructor(config: TestConfiguration);
    runTestSuite(suite: TestSuite): Promise<TestResult[]>;
    runAccessControlTests(suite: TestSuite): Promise<TestResult[]>;
    runDataBehaviorTests(suite: TestSuite): Promise<TestResult[]>;
    runContractTests(suite: TestSuite): Promise<TestResult[]>;
    runDatasetHealthTests(suite: TestSuite): Promise<TestResult[]>;
    generateComplianceReport(results: TestResult[]): Promise<any>;
    isCompliant(results: TestResult[]): boolean;
}
