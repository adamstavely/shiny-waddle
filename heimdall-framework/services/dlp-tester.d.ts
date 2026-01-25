import { TestResult, DLPPattern, DataOperation, User, TestQuery } from '../core/types';
export interface DLPTesterConfig {
    patterns?: DLPPattern[];
    bulkExportLimits?: {
        csv?: number;
        json?: number;
        excel?: number;
        api?: number;
    };
    piiDetectionRules?: Array<{
        fieldName: string;
        pattern: RegExp;
        severity: 'critical' | 'high' | 'medium' | 'low';
    }>;
}
export declare class DLPTester {
    private patterns;
    private config;
    constructor(config?: DLPTesterConfig | DLPPattern[]);
    testDataExfiltration(user: User, dataOperation: DataOperation): Promise<TestResult>;
    validateAPIResponse(apiResponse: any, allowedFields: string[], piiFields: string[]): Promise<TestResult>;
    testQueryResultValidation(query: TestQuery, user: User, expectedFields: string[]): Promise<TestResult>;
    testBulkExportControls(user: User, exportRequest: {
        type: 'csv' | 'json' | 'excel' | 'api';
        recordCount: number;
    }): Promise<TestResult>;
    detectSensitiveDataLeakage(response: any, patterns: DLPPattern[]): Promise<TestResult[]>;
    private getDefaultPatterns;
    private detectSensitiveData;
    private calculateDataSize;
    private extractFields;
    private extractQueryFields;
}
