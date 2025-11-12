import { User, TestQuery, Filter, DataBehaviorConfig } from '../core/types';
export interface DataBehaviorTestInput {
    user: User;
    query: TestQuery;
    expectedFields?: string[];
    requiredFilters?: Filter[];
    disallowedJoins?: string[];
}
export interface DataBehaviorTestResult {
    compliant: boolean;
    violations: string[];
    queryAnalysis: {
        fieldsUsed: string[];
        joinsUsed: string[];
        filtersApplied: Filter[];
        aggregationsApplied: string[];
        piiFieldsExposed: string[];
    };
    recommendations: string[];
}
export declare class DataBehaviorTester {
    private config;
    private queryAnalyzer;
    private piiValidator;
    constructor(config: DataBehaviorConfig);
    testQuery(input: DataBehaviorTestInput): Promise<DataBehaviorTestResult>;
    private isOverBroadQuery;
    private findMissingFilters;
    private filterValuesMatch;
    private isPiiMasked;
}
