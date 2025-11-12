import { TestQuery, User } from '../core/types';
import { QueryAnalysis } from './query-analyzer';
export interface AdvancedQueryAnalysis extends QueryAnalysis {
    queryPlan?: QueryPlan;
    rlsPolicies?: RLSPolicy[];
    clsPolicies?: CLSPolicy[];
    performanceMetrics?: PerformanceMetrics;
    securityIssues?: SecurityIssue[];
}
export interface QueryPlan {
    plan: any;
    estimatedCost?: number;
    estimatedRows?: number;
    actualRows?: number;
    executionTime?: number;
    operations: QueryOperation[];
}
export interface QueryOperation {
    type: string;
    table?: string;
    index?: string;
    filter?: string;
    cost?: number;
    rows?: number;
}
export interface RLSPolicy {
    table: string;
    policyName: string;
    policyDefinition: string;
    applicable: boolean;
}
export interface CLSPolicy {
    table: string;
    column: string;
    policyType: 'masking' | 'encryption' | 'redaction';
    policyDefinition: string;
    applicable: boolean;
}
export interface PerformanceMetrics {
    executionTime: number;
    rowsExamined: number;
    rowsReturned: number;
    indexUsage: string[];
    fullTableScans: string[];
    slowQuery: boolean;
}
export interface SecurityIssue {
    severity: 'critical' | 'high' | 'medium' | 'low';
    type: 'sql-injection' | 'privilege-escalation' | 'data-leakage' | 'bypass-attempt';
    description: string;
    location?: string;
    recommendation?: string;
}
export declare class AdvancedQueryAnalyzer {
    analyzeAdvanced(query: TestQuery, user?: User, connection?: any): Promise<AdvancedQueryAnalysis>;
    private analyzeBase;
    analyzeQueryPlan(sql: string, connection?: any): Promise<QueryPlan | undefined>;
    private parseQueryPlan;
    analyzeRLSPolicies(sql: string, user?: User): Promise<RLSPolicy[]>;
    analyzeCLSPolicies(sql: string, user?: User): Promise<CLSPolicy[]>;
    detectSecurityIssues(sql: string): Promise<SecurityIssue[]>;
    private detectSQLInjection;
    private detectPrivilegeEscalation;
    private detectDataLeakage;
    private detectRLSBypass;
    analyzePerformance(query: TestQuery, connection?: any): Promise<PerformanceMetrics | undefined>;
    private isPIIColumn;
    validateRLSCompliance(analysis: AdvancedQueryAnalysis, user?: User): {
        compliant: boolean;
        violations: string[];
    };
    validateCLSCompliance(analysis: AdvancedQueryAnalysis, user?: User): {
        compliant: boolean;
        violations: string[];
    };
}
