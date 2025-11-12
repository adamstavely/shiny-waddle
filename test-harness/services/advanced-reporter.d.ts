import { TestResult, ComplianceScore } from '../core/types';
import { RiskScore } from './risk-scorer';
import { TrendAnalysis } from './compliance-trend-analyzer';
export interface ReportConfig {
    type: 'executive' | 'regulatory' | 'technical' | 'custom';
    format: 'pdf' | 'html' | 'excel' | 'powerpoint' | 'json';
    template?: string;
    includeCharts?: boolean;
    includeTrends?: boolean;
    includeRiskScores?: boolean;
    customSections?: string[];
}
export interface ExecutiveReport {
    summary: {
        overallScore: number;
        trend: string;
        criticalIssues: number;
        riskLevel: string;
    };
    keyMetrics: {
        complianceScore: number;
        testCoverage: number;
        policyCompliance: number;
        dataProtection: number;
    };
    trends: TrendAnalysis;
    topRisks: RiskScore[];
    recommendations: string[];
}
export interface RegulatoryReport {
    framework: 'gdpr' | 'hipaa' | 'soc2' | 'pci-dss' | 'custom';
    complianceStatus: Record<string, boolean>;
    evidence: TestResult[];
    gaps: string[];
    remediationPlan: string[];
    certification: {
        compliant: boolean;
        score: number;
        expirationDate?: Date;
    };
}
export declare class AdvancedReporter {
    generateExecutiveReport(scores: ComplianceScore[], riskScores: RiskScore[], trends: TrendAnalysis): Promise<ExecutiveReport>;
    generateRegulatoryReport(framework: RegulatoryReport['framework'], testResults: TestResult[], scores: ComplianceScore[]): Promise<RegulatoryReport>;
    generateCustomReport(config: ReportConfig, data: {
        testResults?: TestResult[];
        scores?: ComplianceScore[];
        riskScores?: RiskScore[];
        trends?: TrendAnalysis;
    }): Promise<any>;
    exportReport(report: any, config: ReportConfig, outputPath: string): Promise<string>;
    private exportHTML;
    private exportPDF;
    private exportPDFWithPDFKit;
    private exportExcel;
    private exportPowerPoint;
    private exportJSON;
    private generateHTML;
    private generateReportContent;
    private generateExecutiveContent;
    private generateRegulatoryContent;
    private generateCharts;
    private calculateCategoryBreakdown;
    private calculateOverallScore;
    private calculateTestCoverage;
    private calculatePolicyCompliance;
    private calculateDataProtection;
    private determineRiskLevel;
    private generateExecutiveRecommendations;
    private checkFrameworkCompliance;
    private checkGDPRDataMinimization;
    private checkGDPRRightToAccess;
    private checkGDPRRightToErasure;
    private checkGDPRDataPortability;
    private checkHIPAAAccessControls;
    private checkHIPAAAuditControls;
    private checkHIPAATransmissionSecurity;
    private collectEvidence;
    private identifyGaps;
    private createRemediationPlan;
    private calculateFrameworkScore;
}
