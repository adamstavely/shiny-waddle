import { Validator, ValidatorMetadata } from './validator-registry';
import { TestResult, TestSuite } from './types';
export declare abstract class BaseValidator implements Validator {
    abstract readonly id: string;
    abstract readonly name: string;
    abstract readonly description: string;
    abstract readonly testType: string;
    abstract readonly version: string;
    abstract readonly metadata?: ValidatorMetadata;
    protected config: any;
    constructor(config?: any);
    canHandle(suite: TestSuite): boolean;
    runTests(suite: TestSuite): Promise<TestResult[]>;
    protected abstract runTestsInternal(suite: TestSuite): Promise<TestResult[]>;
    protected shouldRun(suite: TestSuite): boolean;
    validateConfig?(config: any): {
        valid: boolean;
        errors: string[];
    };
    private validateConfiguration;
    protected createTestResult(testName: string, passed: boolean, details: any, error?: string): TestResult;
    protected createPassedResult(testName: string, details?: any): TestResult;
    protected createFailedResult(testName: string, reason: string, details?: any): TestResult;
    private capitalize;
}
