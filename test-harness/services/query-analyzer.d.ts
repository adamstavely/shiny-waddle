import { TestQuery, DataBehaviorConfig } from '../core/types';
import { Filter } from '../core/types';
export interface QueryAnalysis {
    fieldsUsed: string[];
    joinsUsed: string[];
    filtersApplied: Filter[];
    aggregationsApplied: string[];
    hasLimit: boolean;
    limit?: number;
    hasOrderBy: boolean;
    queryType: 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'API';
}
export declare class QueryAnalyzer {
    private config;
    constructor(config: DataBehaviorConfig);
    analyze(query: TestQuery): Promise<QueryAnalysis>;
    private analyzeSqlQuery;
    private analyzeApiRequest;
    private extractFields;
    private extractJoins;
    private extractFilters;
    private parseCondition;
    private extractAggregations;
    private extractFieldsFromApiRequest;
    private extractFiltersFromApiRequest;
}
