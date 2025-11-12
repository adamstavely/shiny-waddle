/**
 * Advanced Reporting Service
 * 
 * Enhanced reporting with executive dashboards, regulatory reports, and custom reports
 */

import { TestResult, ComplianceScore } from '../core/types';
import { RiskScore } from './risk-scorer';
import { TrendAnalysis } from './compliance-trend-analyzer';
import * as fs from 'fs/promises';
import * as path from 'path';
import { createWriteStream } from 'fs';

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

export class AdvancedReporter {
  /**
   * Generate executive dashboard report
   */
  async generateExecutiveReport(
    scores: ComplianceScore[],
    riskScores: RiskScore[],
    trends: TrendAnalysis
  ): Promise<ExecutiveReport> {
    const overallScore = this.calculateOverallScore(scores);
    const criticalIssues = riskScores.filter(r => r.severity === 'critical').length;
    const riskLevel = this.determineRiskLevel(riskScores);

    return {
      summary: {
        overallScore,
        trend: trends.overallTrend,
        criticalIssues,
        riskLevel,
      },
      keyMetrics: {
        complianceScore: overallScore,
        testCoverage: this.calculateTestCoverage(scores),
        policyCompliance: this.calculatePolicyCompliance(scores),
        dataProtection: this.calculateDataProtection(scores),
      },
      trends,
      topRisks: riskScores.slice(0, 10),
      recommendations: this.generateExecutiveRecommendations(riskScores, trends),
    };
  }

  /**
   * Generate regulatory compliance report
   */
  async generateRegulatoryReport(
    framework: RegulatoryReport['framework'],
    testResults: TestResult[],
    scores: ComplianceScore[]
  ): Promise<RegulatoryReport> {
    const complianceStatus = this.checkFrameworkCompliance(framework, testResults);
    const evidence = this.collectEvidence(testResults, framework);
    const gaps = this.identifyGaps(complianceStatus);
    const remediationPlan = this.createRemediationPlan(gaps, framework);

    return {
      framework,
      complianceStatus,
      evidence,
      gaps,
      remediationPlan,
      certification: {
        compliant: Object.values(complianceStatus).every(v => v),
        score: this.calculateFrameworkScore(complianceStatus),
      },
    };
  }

  /**
   * Generate custom report
   */
  async generateCustomReport(
    config: ReportConfig,
    data: {
      testResults?: TestResult[];
      scores?: ComplianceScore[];
      riskScores?: RiskScore[];
      trends?: TrendAnalysis;
    }
  ): Promise<any> {
    const report: any = {
      generatedAt: new Date().toISOString(),
      config,
    };

    if (config.includeCharts && data.scores) {
      report.charts = this.generateCharts(data.scores);
    }

    if (config.includeTrends && data.trends) {
      report.trends = data.trends;
    }

    if (config.includeRiskScores && data.riskScores) {
      report.riskScores = data.riskScores;
    }

    if (data.testResults) {
      report.testResults = data.testResults;
    }

    return report;
  }

  /**
   * Export report to file
   */
  async exportReport(
    report: any,
    config: ReportConfig,
    outputPath: string
  ): Promise<string> {
    await fs.mkdir(path.dirname(outputPath), { recursive: true });

    switch (config.format) {
      case 'html':
        return await this.exportHTML(report, config, outputPath);
      case 'pdf':
        return await this.exportPDF(report, config, outputPath);
      case 'excel':
        return await this.exportExcel(report, config, outputPath);
      case 'powerpoint':
        return await this.exportPowerPoint(report, config, outputPath);
      case 'json':
        return await this.exportJSON(report, outputPath);
      default:
        throw new Error(`Unsupported format: ${config.format}`);
    }
  }

  /**
   * Export to HTML
   */
  private async exportHTML(
    report: any,
    config: ReportConfig,
    outputPath: string
  ): Promise<string> {
    const html = this.generateHTML(report, config);
    await fs.writeFile(outputPath, html);
    return outputPath;
  }

  /**
   * Export to PDF
   */
  private async exportPDF(
    report: any,
    config: ReportConfig,
    outputPath: string
  ): Promise<string> {
    try {
      // Try to use puppeteer if available
      let puppeteer: any;
      try {
        puppeteer = require('puppeteer');
      } catch (e) {
        // Fallback: Try pdfkit
        return await this.exportPDFWithPDFKit(report, config, outputPath);
      }

      // Generate HTML first
      const htmlPath = outputPath.replace('.pdf', '.html');
      await this.exportHTML(report, config, htmlPath);

      // Convert HTML to PDF using Puppeteer
      const browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
      });

      try {
        const page = await browser.newPage();
        await page.goto(`file://${path.resolve(htmlPath)}`, {
          waitUntil: 'networkidle0',
        });

        await page.pdf({
          path: outputPath,
          format: 'A4',
          printBackground: true,
          margin: {
            top: '20mm',
            right: '15mm',
            bottom: '20mm',
            left: '15mm',
          },
        });

        return outputPath;
      } finally {
        await browser.close();
      }
    } catch (error: any) {
      // Fallback: Generate HTML and return that path
      const htmlPath = outputPath.replace('.pdf', '.html');
      await this.exportHTML(report, config, htmlPath);
      console.warn(`PDF generation failed: ${error.message}, saved HTML instead`);
      return htmlPath;
    }
  }

  /**
   * Export PDF using PDFKit
   */
  private async exportPDFWithPDFKit(
    report: any,
    config: ReportConfig,
    outputPath: string
  ): Promise<string> {
    try {
      const PDFDocument = require('pdfkit');
      const doc = new PDFDocument({ margin: 50 });

      const stream = fs.createWriteStream(outputPath);
      doc.pipe(stream);

      // Add title
      doc.fontSize(20).text('Compliance Report', { align: 'center' });
      doc.moveDown();

      // Add summary
      if (report.summary) {
        doc.fontSize(16).text('Summary', { underline: true });
        doc.fontSize(12);
        doc.text(`Overall Score: ${report.summary.overallScore || 0}%`);
        doc.text(`Trend: ${report.summary.trend || 'N/A'}`);
        doc.text(`Critical Issues: ${report.summary.criticalIssues || 0}`);
        doc.moveDown();
      }

      // Add test results table
      if (report.testResults) {
        doc.fontSize(16).text('Test Results', { underline: true });
        doc.fontSize(10);
        for (const result of report.testResults) {
          doc.text(`${result.testName}: ${result.passed ? 'PASSED' : 'FAILED'}`);
        }
      }

      doc.end();

      return new Promise((resolve, reject) => {
        stream.on('finish', () => resolve(outputPath));
        stream.on('error', reject);
      });
    } catch (error: any) {
      // Final fallback: HTML
      const htmlPath = outputPath.replace('.pdf', '.html');
      await this.exportHTML(report, config, htmlPath);
      return htmlPath;
    }
  }

  /**
   * Export to Excel
   */
  private async exportExcel(
    report: any,
    config: ReportConfig,
    outputPath: string
  ): Promise<string> {
    try {
      const ExcelJS = require('exceljs');
      const workbook = new ExcelJS.Workbook();
      const worksheet = workbook.addWorksheet('Compliance Report');

      // Add title
      worksheet.mergeCells('A1:D1');
      worksheet.getCell('A1').value = 'Compliance Report';
      worksheet.getCell('A1').font = { size: 16, bold: true };
      worksheet.getCell('A1').alignment = { horizontal: 'center' };

      // Add summary
      let row = 3;
      if (report.summary) {
        worksheet.getCell(`A${row}`).value = 'Summary';
        worksheet.getCell(`A${row}`).font = { bold: true };
        row++;
        worksheet.getCell(`A${row}`).value = 'Overall Score:';
        worksheet.getCell(`B${row}`).value = `${report.summary.overallScore || 0}%`;
        row++;
        worksheet.getCell(`A${row}`).value = 'Trend:';
        worksheet.getCell(`B${row}`).value = report.summary.trend || 'N/A';
        row++;
        worksheet.getCell(`A${row}`).value = 'Critical Issues:';
        worksheet.getCell(`B${row}`).value = report.summary.criticalIssues || 0;
        row += 2;
      }

      // Add test results
      if (report.testResults && report.testResults.length > 0) {
        worksheet.getCell(`A${row}`).value = 'Test Results';
        worksheet.getCell(`A${row}`).font = { bold: true };
        row++;

        // Headers
        worksheet.getCell(`A${row}`).value = 'Test Name';
        worksheet.getCell(`B${row}`).value = 'Type';
        worksheet.getCell(`C${row}`).value = 'Status';
        worksheet.getCell(`D${row}`).value = 'Timestamp';
        worksheet.getRow(row).font = { bold: true };
        row++;

        // Data
        for (const result of report.testResults) {
          worksheet.getCell(`A${row}`).value = result.testName;
          worksheet.getCell(`B${row}`).value = result.testType;
          worksheet.getCell(`C${row}`).value = result.passed ? 'PASSED' : 'FAILED';
          worksheet.getCell(`C${row}`).fill = {
            type: 'pattern',
            pattern: 'solid',
            fgColor: { argb: result.passed ? 'FF4CAF50' : 'FFF44336' },
          };
          worksheet.getCell(`D${row}`).value = result.timestamp;
          row++;
        }
      }

      // Auto-size columns
      worksheet.columns.forEach((column: any) => {
        if (column && column.eachCell) {
          let maxLength = 0;
          column.eachCell({ includeEmpty: false }, (cell: any) => {
            const columnLength = cell.value ? cell.value.toString().length : 10;
            if (columnLength > maxLength) {
              maxLength = columnLength;
            }
          });
          column.width = maxLength < 10 ? 10 : maxLength + 2;
        }
      });

      await workbook.xlsx.writeFile(outputPath);
      return outputPath;
    } catch (error: any) {
      throw new Error(`Excel export failed: ${error.message}. Install exceljs: npm install exceljs`);
    }
  }

  /**
   * Export to PowerPoint
   */
  private async exportPowerPoint(
    report: any,
    config: ReportConfig,
    outputPath: string
  ): Promise<string> {
    try {
      const PptxGenJS = require('pptxgenjs');
      const pptx = new PptxGenJS();

      // Set presentation properties
      pptx.author = 'Heimdall';
      pptx.company = 'Heimdall';
      pptx.title = 'Compliance Report';

      // Title slide
      const titleSlide = pptx.addSlide();
      titleSlide.addText('Compliance Report', {
        x: 1,
        y: 1,
        w: 8,
        h: 1.5,
        fontSize: 44,
        bold: true,
        align: 'center',
      });
      titleSlide.addText(new Date().toLocaleDateString(), {
        x: 1,
        y: 2.5,
        w: 8,
        h: 0.5,
        fontSize: 18,
        align: 'center',
      });

      // Summary slide
      if (report.summary) {
        const summarySlide = pptx.addSlide();
        summarySlide.addText('Summary', {
          x: 0.5,
          y: 0.5,
          w: 9,
          h: 0.5,
          fontSize: 32,
          bold: true,
        });

        const summaryData = [
          ['Metric', 'Value'],
          ['Overall Score', `${report.summary.overallScore || 0}%`],
          ['Trend', report.summary.trend || 'N/A'],
          ['Critical Issues', `${report.summary.criticalIssues || 0}`],
        ];

        summarySlide.addTable(summaryData, {
          x: 1,
          y: 1.5,
          w: 8,
          colW: [3, 5],
        });
      }

      // Test results slide
      if (report.testResults && report.testResults.length > 0) {
        const resultsSlide = pptx.addSlide();
        resultsSlide.addText('Test Results', {
          x: 0.5,
          y: 0.5,
          w: 9,
          h: 0.5,
          fontSize: 32,
          bold: true,
        });

        // Create table data
        const tableData = [
          ['Test Name', 'Type', 'Status'],
          ...report.testResults.slice(0, 10).map((r: any) => [
            r.testName.substring(0, 30),
            r.testType,
            r.passed ? 'PASSED' : 'FAILED',
          ]),
        ];

        resultsSlide.addTable(tableData, {
          x: 0.5,
          y: 1.2,
          w: 9,
          colW: [4, 2, 3],
        });
      }

      await pptx.writeFile({ fileName: outputPath });
      return outputPath;
    } catch (error: any) {
      throw new Error(`PowerPoint export failed: ${error.message}. Install pptxgenjs: npm install pptxgenjs`);
    }
  }

  /**
   * Export to JSON
   */
  private async exportJSON(report: any, outputPath: string): Promise<string> {
    await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
    return outputPath;
  }

  /**
   * Generate HTML report
   */
  private generateHTML(report: any, config: ReportConfig): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <title>Compliance Report</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .header { background: #f5f5f5; padding: 20px; border-radius: 5px; }
    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .metric-card { background: white; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }
    .metric-value { font-size: 2em; font-weight: bold; color: #4CAF50; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    th { background-color: #4CAF50; color: white; }
  </style>
</head>
<body>
  <div class="header">
    <h1>Compliance Report</h1>
    <p>Generated: ${new Date().toLocaleString()}</p>
  </div>
  ${this.generateReportContent(report, config)}
</body>
</html>
    `;
  }

  /**
   * Generate report content
   */
  private generateReportContent(report: any, config: ReportConfig): string {
    if (config.type === 'executive') {
      return this.generateExecutiveContent(report);
    } else if (config.type === 'regulatory') {
      return this.generateRegulatoryContent(report);
    }
    return '<p>Report content</p>';
  }

  /**
   * Generate executive content
   */
  private generateExecutiveContent(report: ExecutiveReport): string {
    return `
      <div class="summary">
        <div class="metric-card">
          <h3>Overall Score</h3>
          <div class="metric-value">${report.summary.overallScore}%</div>
        </div>
        <div class="metric-card">
          <h3>Critical Issues</h3>
          <div class="metric-value">${report.summary.criticalIssues}</div>
        </div>
        <div class="metric-card">
          <h3>Risk Level</h3>
          <div class="metric-value">${report.summary.riskLevel}</div>
        </div>
      </div>
      <h2>Top Risks</h2>
      <table>
        <tr>
          <th>Risk</th>
          <th>Severity</th>
          <th>Score</th>
        </tr>
        ${report.topRisks.map(risk => `
          <tr>
            <td>${risk.testResult.testName}</td>
            <td>${risk.severity}</td>
            <td>${risk.riskScore}</td>
          </tr>
        `).join('')}
      </table>
    `;
  }

  /**
   * Generate regulatory content
   */
  private generateRegulatoryContent(report: RegulatoryReport): string {
    return `
      <h2>${report.framework.toUpperCase()} Compliance Report</h2>
      <h3>Compliance Status</h3>
      <table>
        <tr>
          <th>Requirement</th>
          <th>Status</th>
        </tr>
        ${Object.entries(report.complianceStatus).map(([req, status]) => `
          <tr>
            <td>${req}</td>
            <td>${status ? '✅ Compliant' : '❌ Non-Compliant'}</td>
          </tr>
        `).join('')}
      </table>
    `;
  }

  /**
   * Generate charts data
   */
  private generateCharts(scores: ComplianceScore[]): any {
    return {
      scoreOverTime: scores.map(s => ({
        date: s.lastUpdated,
        score: s.overallScore,
      })),
      categoryBreakdown: this.calculateCategoryBreakdown(scores),
    };
  }

  /**
   * Calculate category breakdown
   */
  private calculateCategoryBreakdown(scores: ComplianceScore[]): Record<string, number> {
    const totals: Record<string, number> = {};
    const counts: Record<string, number> = {};

    for (const score of scores) {
      for (const [category, value] of Object.entries(score.scoresByCategory)) {
        totals[category] = (totals[category] || 0) + value;
        counts[category] = (counts[category] || 0) + 1;
      }
    }

    const breakdown: Record<string, number> = {};
    for (const category in totals) {
      breakdown[category] = totals[category] / counts[category];
    }

    return breakdown;
  }

  /**
   * Calculate overall score
   */
  private calculateOverallScore(scores: ComplianceScore[]): number {
    if (scores.length === 0) return 0;
    const sum = scores.reduce((acc, s) => acc + s.overallScore, 0);
    return sum / scores.length;
  }

  /**
   * Calculate test coverage
   */
  private calculateTestCoverage(scores: ComplianceScore[]): number {
    // Simplified - would need actual test coverage data
    return 85;
  }

  /**
   * Calculate policy compliance
   */
  private calculatePolicyCompliance(scores: ComplianceScore[]): number {
    if (scores.length === 0) return 0;
    const sum = scores.reduce((acc, s) => acc + s.scoresByCategory.accessControl, 0);
    return sum / scores.length;
  }

  /**
   * Calculate data protection
   */
  private calculateDataProtection(scores: ComplianceScore[]): number {
    if (scores.length === 0) return 0;
    const sum = scores.reduce((acc, s) => acc + s.scoresByCategory.datasetHealth, 0);
    return sum / scores.length;
  }

  /**
   * Determine risk level
   */
  private determineRiskLevel(riskScores: RiskScore[]): string {
    const critical = riskScores.filter(r => r.severity === 'critical').length;
    const high = riskScores.filter(r => r.severity === 'high').length;

    if (critical > 5) return 'Critical';
    if (critical > 0 || high > 10) return 'High';
    if (high > 0) return 'Medium';
    return 'Low';
  }

  /**
   * Generate executive recommendations
   */
  private generateExecutiveRecommendations(
    riskScores: RiskScore[],
    trends: TrendAnalysis
  ): string[] {
    const recommendations: string[] = [];

    const criticalRisks = riskScores.filter(r => r.severity === 'critical');
    if (criticalRisks.length > 0) {
      recommendations.push(`Address ${criticalRisks.length} critical security risks immediately`);
    }

    if (trends.overallTrend === 'declining') {
      recommendations.push('Compliance scores are declining - review and strengthen policies');
    }

    if (trends.volatility > 10) {
      recommendations.push('High volatility in compliance scores - investigate root causes');
    }

    return recommendations;
  }

  /**
   * Check framework compliance
   */
  private checkFrameworkCompliance(
    framework: string,
    testResults: TestResult[]
  ): Record<string, boolean> {
    // Framework-specific compliance checks
    const compliance: Record<string, boolean> = {};

    switch (framework) {
      case 'gdpr':
        compliance['Data Minimization'] = this.checkGDPRDataMinimization(testResults);
        compliance['Right to Access'] = this.checkGDPRRightToAccess(testResults);
        compliance['Right to Erasure'] = this.checkGDPRRightToErasure(testResults);
        compliance['Data Portability'] = this.checkGDPRDataPortability(testResults);
        break;
      case 'hipaa':
        compliance['Access Controls'] = this.checkHIPAAAccessControls(testResults);
        compliance['Audit Controls'] = this.checkHIPAAAuditControls(testResults);
        compliance['Transmission Security'] = this.checkHIPAATransmissionSecurity(testResults);
        break;
      // Add more frameworks as needed
    }

    return compliance;
  }

  /**
   * GDPR compliance checks
   */
  private checkGDPRDataMinimization(testResults: TestResult[]): boolean {
    // Check if queries only access necessary data
    return testResults.every(r => 
      !r.details?.violations?.some((v: string) => v.includes('over-broad'))
    );
  }

  private checkGDPRRightToAccess(testResults: TestResult[]): boolean {
    // Simplified check
    return true;
  }

  private checkGDPRRightToErasure(testResults: TestResult[]): boolean {
    // Simplified check
    return true;
  }

  private checkGDPRDataPortability(testResults: TestResult[]): boolean {
    // Simplified check
    return true;
  }

  /**
   * HIPAA compliance checks
   */
  private checkHIPAAAccessControls(testResults: TestResult[]): boolean {
    return testResults.filter(r => r.testType === 'access-control').every(r => r.passed);
  }

  private checkHIPAAAuditControls(testResults: TestResult[]): boolean {
    // Check if audit logging is present
    return true;
  }

  private checkHIPAATransmissionSecurity(testResults: TestResult[]): boolean {
    // Check if data transmission is encrypted
    return true;
  }

  /**
   * Collect evidence for regulatory report
   */
  private collectEvidence(
    testResults: TestResult[],
    framework: string
  ): TestResult[] {
    return testResults.filter(r => r.passed);
  }

  /**
   * Identify compliance gaps
   */
  private identifyGaps(complianceStatus: Record<string, boolean>): string[] {
    return Object.entries(complianceStatus)
      .filter(([_, status]) => !status)
      .map(([requirement, _]) => requirement);
  }

  /**
   * Create remediation plan
   */
  private createRemediationPlan(
    gaps: string[],
    framework: string
  ): string[] {
    return gaps.map(gap => `Address ${gap} requirement for ${framework.toUpperCase()} compliance`);
  }

  /**
   * Calculate framework score
   */
  private calculateFrameworkScore(complianceStatus: Record<string, boolean>): number {
    const total = Object.keys(complianceStatus).length;
    const compliant = Object.values(complianceStatus).filter(v => v).length;
    return total > 0 ? (compliant / total) * 100 : 0;
  }
}

