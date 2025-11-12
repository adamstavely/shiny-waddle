export interface SecurityHeaderAnalysis {
    header: string;
    present: boolean;
    value?: string;
    valid: boolean;
    issues: string[];
    recommendations: string[];
}
export interface SecurityHeadersReport {
    overallScore: number;
    headers: SecurityHeaderAnalysis[];
    criticalIssues: string[];
    warnings: string[];
}
export declare function analyzeSecurityHeader(headerName: string, headerValue: string | null): SecurityHeaderAnalysis;
export declare function analyzeCORS(headers: Record<string, string>): SecurityHeaderAnalysis;
export declare function analyzeSecurityHeaders(headers: Record<string, string>): SecurityHeadersReport;
