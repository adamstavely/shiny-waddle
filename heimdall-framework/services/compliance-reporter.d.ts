import { TestResult, ReportingConfig } from '../core/types';
export declare class ComplianceReporter {
    private config;
    constructor(config: ReportingConfig);
    generateReport(results: TestResult[]): Promise<any>;
    calculateScores(results: TestResult[]): {
        overall: number;
        byCategory: Record<string, number>;
        byApplication: Record<string, number>;
        byTeam: Record<string, number>;
    };
    private generateSummary;
    private extractApplication;
    private extractTeam;
    private writeReport;
    private generateHtmlReport;
    private generateJunitReport;
}
