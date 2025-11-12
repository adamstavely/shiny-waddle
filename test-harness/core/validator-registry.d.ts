import { TestResult, TestSuite } from './types';
export interface Validator {
    readonly id: string;
    readonly name: string;
    readonly description: string;
    readonly testType: string;
    readonly version: string;
    readonly metadata?: ValidatorMetadata;
    canHandle(suite: TestSuite): boolean;
    runTests(suite: TestSuite): Promise<TestResult[]>;
    validateConfig?(config: any): {
        valid: boolean;
        errors: string[];
    };
}
export interface ValidatorMetadata {
    supportedTestTypes?: string[];
    requiredConfig?: string[];
    optionalConfig?: string[];
    dependencies?: string[];
    tags?: string[];
    exampleConfig?: any;
}
export declare class ValidatorRegistry {
    private validators;
    private validatorsByType;
    register(validator: Validator): void;
    unregister(validatorId: string): void;
    get(validatorId: string): Validator | undefined;
    getByType(testType: string): Validator[];
    getAll(): Validator[];
    findValidatorsForSuite(suite: TestSuite): Validator[];
    list(): Array<{
        id: string;
        name: string;
        testType: string;
        description: string;
    }>;
}
export declare const validatorRegistry: ValidatorRegistry;
