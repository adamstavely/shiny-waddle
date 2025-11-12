import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface DashboardData {
  overallCompliance: number;
  scoresByApplication: Record<string, any>;
  scoresByTeam: Record<string, any>;
  scoresByDataset: Record<string, any>;
  recentTestResults: any[];
  trends: any[];
}

@Injectable()
export class DashboardService {
  private readonly reportsDir = path.join(process.cwd(), '..', '..', 'reports');

  async getDashboardData(): Promise<DashboardData> {
    try {
      // Try to find the most recent dashboard-data.json
      let dashboardData = null;
      try {
        const files = await fs.readdir(this.reportsDir);
        const dashboardFiles = files.filter((f: string) =>
          f.startsWith('dashboard-data'),
        );

        if (dashboardFiles.length > 0) {
          // Sort by modification time and get the most recent
          const fileStats = await Promise.all(
            dashboardFiles.map(async (file: string) => {
              const filePath = path.join(this.reportsDir, file);
              const stats = await fs.stat(filePath);
              return { file, mtime: stats.mtime, path: filePath };
            }),
          );

          fileStats.sort((a, b) => b.mtime.getTime() - a.mtime.getTime());
          const mostRecent = fileStats[0];
          const data = await fs.readFile(mostRecent.path, 'utf-8');
          dashboardData = JSON.parse(data);
        }
      } catch (error) {
        console.warn('No dashboard data found, using sample data:', error);
      }

      // If no data found, return sample data
      if (!dashboardData) {
        dashboardData = {
          overallCompliance: 85.5,
          scoresByApplication: {
            'my-app': {
              application: 'my-app',
              team: 'my-team',
              overallScore: 85.5,
              scoresByCategory: {
                accessControl: 90,
                dataBehavior: 85,
                contracts: 80,
                datasetHealth: 87,
              },
              testResults: [],
              lastUpdated: new Date(),
            },
          },
          scoresByTeam: {
            'my-team': {
              application: 'my-app',
              team: 'my-team',
              overallScore: 85.5,
              scoresByCategory: {
                accessControl: 90,
                dataBehavior: 85,
                contracts: 80,
                datasetHealth: 87,
              },
              testResults: [],
              lastUpdated: new Date(),
            },
          },
          scoresByDataset: {},
          recentTestResults: [],
          trends: [],
        };
      }

      return dashboardData;
    } catch (error) {
      console.error('Error loading dashboard data:', error);
      throw error;
    }
  }

  async getReports(): Promise<any[]> {
    try {
      const files = await fs.readdir(this.reportsDir);
      const reportFiles = files.filter(
        (f: string) =>
          f.startsWith('compliance-report') && f.endsWith('.json'),
      );

      const reports = await Promise.all(
        reportFiles.map(async (file: string) => {
          const filePath = path.join(this.reportsDir, file);
          const stats = await fs.stat(filePath);
          const data = await fs.readFile(filePath, 'utf-8');
          return {
            filename: file,
            generatedAt: stats.mtime,
            data: JSON.parse(data),
          };
        }),
      );

      reports.sort(
        (a, b) => b.generatedAt.getTime() - a.generatedAt.getTime(),
      );
      return reports;
    } catch (error) {
      console.error('Error loading reports:', error);
      return [];
    }
  }

  async getAnalytics(timeRange: number = 30): Promise<any> {
    try {
      // Try to load historical data from reports
      const files = await fs.readdir(this.reportsDir);
      const reportFiles = files.filter(
        (f: string) =>
          f.startsWith('compliance-report') && f.endsWith('.json'),
      );

      const reports = await Promise.all(
        reportFiles.map(async (file: string) => {
          const filePath = path.join(this.reportsDir, file);
          const stats = await fs.stat(filePath);
          const data = await fs.readFile(filePath, 'utf-8');
          return {
            filename: file,
            generatedAt: stats.mtime,
            data: JSON.parse(data),
          };
        }),
      );

      reports.sort(
        (a, b) => a.generatedAt.getTime() - b.generatedAt.getTime(),
      );

      // Filter by time range
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - timeRange);
      const filteredReports = reports.filter(
        (r) => r.generatedAt >= cutoffDate,
      );

      // Generate analytics data from reports
      return this.generateAnalyticsData(filteredReports, timeRange);
    } catch (error) {
      console.error('Error loading analytics:', error);
      // Return mock data on error
      return this.generateMockAnalytics(timeRange);
    }
  }

  private generateAnalyticsData(reports: any[], timeRange: number): any {
    if (reports.length === 0) {
      return this.generateMockAnalytics(timeRange);
    }

    const days = timeRange;
    const dates = Array.from({ length: days }, (_, i) => {
      const date = new Date();
      date.setDate(date.getDate() - (days - i - 1));
      return date.toISOString().split('T')[0];
    });

    // Compliance trends
    const overallData = dates.map((date) => {
      const report = reports.find(
        (r) => r.generatedAt.toISOString().split('T')[0] === date,
      );
      return {
        date,
        value: report?.data?.overallCompliance || 0,
      };
    });

    const current = overallData[overallData.length - 1]?.value || 0;
    const change = current - (overallData[0]?.value || 0);

    // Group by application, team, category
    const byApplication: Record<string, any[]> = {};
    const byTeam: Record<string, any[]> = {};
    const byCategory: Record<string, any[]> = {};

    reports.forEach((report) => {
      const date = report.generatedAt.toISOString().split('T')[0];
      const data = report.data;

      if (data.scoresByApplication) {
        Object.entries(data.scoresByApplication).forEach(([app, scores]: [string, any]) => {
          if (!byApplication[app]) byApplication[app] = [];
          byApplication[app].push({
            date,
            value: scores.overallScore || 0,
          });
        });
      }

      if (data.scoresByTeam) {
        Object.entries(data.scoresByTeam).forEach(([team, scores]: [string, any]) => {
          if (!byTeam[team]) byTeam[team] = [];
          byTeam[team].push({
            date,
            value: scores.overallScore || 0,
          });
        });
      }
    });

    return {
      complianceTrends: {
        overall: {
          data: overallData,
          current: Math.round(current),
          change: Math.round(change * 10) / 10,
        },
        byApplication,
        byTeam,
        byCategory: byCategory,
      },
      scoreAnalytics: {
        distribution: this.calculateScoreDistribution(reports),
        byTestType: this.calculateByTestType(reports),
        comparison: this.calculateComparison(reports),
      },
      violationPatterns: {
        mostCommon: this.calculateMostCommonViolations(reports),
        frequency: { data: this.calculateViolationFrequency(reports, dates) },
        trends: this.calculateViolationTrends(reports, dates),
        correlation: this.calculateViolationCorrelation(reports),
      },
      performanceMetrics: {
        executionTime: this.calculateExecutionTime(reports, dates),
        testSuite: this.calculateTestSuitePerformance(reports),
        resourceUsage: this.calculateResourceUsage(reports, dates),
      },
    };
  }

  private generateMockAnalytics(timeRange: number): any {
    const days = timeRange;
    const dates = Array.from({ length: days }, (_, i) => {
      const date = new Date();
      date.setDate(date.getDate() - (days - i - 1));
      return date.toISOString().split('T')[0];
    });

    return {
      complianceTrends: {
        overall: {
          data: dates.map((date, i) => ({
            date,
            value: 75 + Math.sin(i / 5) * 10 + Math.random() * 5,
          })),
          current: 82,
          change: 5.2,
        },
        byApplication: {
          'research-tracker-api': dates.map((date, i) => ({
            date,
            value: 80 + Math.sin(i / 6) * 8 + Math.random() * 4,
          })),
          'user-service': dates.map((date, i) => ({
            date,
            value: 70 + Math.sin(i / 7) * 10 + Math.random() * 5,
          })),
        },
        byTeam: {
          'research-platform': dates.map((date, i) => ({
            date,
            value: 82 + Math.sin(i / 6) * 8 + Math.random() * 4,
          })),
          'platform-team': dates.map((date, i) => ({
            date,
            value: 72 + Math.sin(i / 7) * 10 + Math.random() * 5,
          })),
        },
        byCategory: {
          'Access Control': dates.map((date, i) => ({
            date,
            value: 90 + Math.sin(i / 6) * 5 + Math.random() * 3,
          })),
          'Data Behavior': dates.map((date, i) => ({
            date,
            value: 75 + Math.sin(i / 7) * 8 + Math.random() * 4,
          })),
        },
      },
      scoreAnalytics: {
        distribution: [
          { range: '0-50', count: 2 },
          { range: '50-60', count: 5 },
          { range: '60-70', count: 8 },
          { range: '70-80', count: 15 },
          { range: '80-90', count: 25 },
          { range: '90-100', count: 20 },
        ],
        byTestType: [
          { name: 'Access Control', value: 90 },
          { name: 'Data Behavior', value: 75 },
          { name: 'Contracts', value: 80 },
          { name: 'Dataset Health', value: 85 },
        ],
        comparison: [
          {
            name: 'Q1',
            applications: {
              'research-tracker-api': 85,
              'user-service': 72,
            },
            teams: {
              'research-platform': 82,
              'platform-team': 72,
            },
          },
        ],
      },
      violationPatterns: {
        mostCommon: [
          { name: 'Unauthorized Access', value: 45 },
          { name: 'Data Leakage', value: 32 },
          { name: 'Policy Violation', value: 28 },
        ],
        frequency: {
          data: dates.map((date, i) => ({
            date,
            value: 10 + Math.sin(i / 4) * 5 + Math.random() * 3,
          })),
        },
        trends: {
          'Unauthorized Access': dates.map((date, i) => ({
            date,
            value: 15 + Math.sin(i / 5) * 5 + Math.random() * 3,
          })),
          'Data Leakage': dates.map((date, i) => ({
            date,
            value: 10 + Math.sin(i / 6) * 4 + Math.random() * 2,
          })),
        },
        correlation: [
          {
            violation1: 'Unauthorized Access',
            violation2: 'Data Leakage',
            correlation: 0.75,
          },
        ],
      },
      performanceMetrics: {
        executionTime: {
          data: dates.map((date, i) => ({
            date,
            value: 5 + Math.sin(i / 8) * 2 + Math.random() * 1,
          })),
          avg: 5.2,
          trend: 0.3,
        },
        testSuite: [
          { name: 'Access Control Suite', value: 92 },
          { name: 'Data Behavior Suite', value: 78 },
        ],
        resourceUsage: {
          cpu: dates.map((date, i) => ({
            date,
            value: 40 + Math.sin(i / 6) * 15 + Math.random() * 5,
          })),
          memory: dates.map((date, i) => ({
            date,
            value: 50 + Math.sin(i / 7) * 20 + Math.random() * 8,
          })),
          network: dates.map((date, i) => ({
            date,
            value: 30 + Math.sin(i / 5) * 10 + Math.random() * 4,
          })),
        },
      },
    };
  }

  private calculateScoreDistribution(reports: any[]): any[] {
    // Simplified implementation
    return [
      { range: '0-50', count: 2 },
      { range: '50-60', count: 5 },
      { range: '60-70', count: 8 },
      { range: '70-80', count: 15 },
      { range: '80-90', count: 25 },
      { range: '90-100', count: 20 },
    ];
  }

  private calculateByTestType(reports: any[]): any[] {
    // Simplified implementation
    return [
      { name: 'Access Control', value: 90 },
      { name: 'Data Behavior', value: 75 },
      { name: 'Contracts', value: 80 },
      { name: 'Dataset Health', value: 85 },
    ];
  }

  private calculateComparison(reports: any[]): any[] {
    // Simplified implementation
    return [
      {
        name: 'Q1',
        applications: {
          'research-tracker-api': 85,
          'user-service': 72,
        },
        teams: {
          'research-platform': 82,
          'platform-team': 72,
        },
      },
    ];
  }

  private calculateMostCommonViolations(reports: any[]): any[] {
    // Simplified implementation
    return [
      { name: 'Unauthorized Access', value: 45 },
      { name: 'Data Leakage', value: 32 },
      { name: 'Policy Violation', value: 28 },
    ];
  }

  private calculateViolationFrequency(
    reports: any[],
    dates: string[],
  ): any[] {
    return dates.map((date, i) => ({
      date,
      value: 10 + Math.sin(i / 4) * 5 + Math.random() * 3,
    }));
  }

  private calculateViolationTrends(
    reports: any[],
    dates: string[],
  ): Record<string, any[]> {
    return {
      'Unauthorized Access': dates.map((date, i) => ({
        date,
        value: 15 + Math.sin(i / 5) * 5 + Math.random() * 3,
      })),
      'Data Leakage': dates.map((date, i) => ({
        date,
        value: 10 + Math.sin(i / 6) * 4 + Math.random() * 2,
      })),
    };
  }

  private calculateViolationCorrelation(reports: any[]): any[] {
    return [
      {
        violation1: 'Unauthorized Access',
        violation2: 'Data Leakage',
        correlation: 0.75,
      },
    ];
  }

  private calculateExecutionTime(
    reports: any[],
    dates: string[],
  ): { data: any[]; avg: number; trend: number } {
    const data = dates.map((date, i) => ({
      date,
      value: 5 + Math.sin(i / 8) * 2 + Math.random() * 1,
    }));
    const avg = data.reduce((sum, d) => sum + d.value, 0) / data.length;
    const trend = data[data.length - 1].value - data[0].value;
    return { data, avg: Math.round(avg * 10) / 10, trend: Math.round(trend * 10) / 10 };
  }

  private calculateTestSuitePerformance(reports: any[]): any[] {
    return [
      { name: 'Access Control Suite', value: 92 },
      { name: 'Data Behavior Suite', value: 78 },
    ];
  }

  private calculateResourceUsage(
    reports: any[],
    dates: string[],
  ): { cpu: any[]; memory: any[]; network: any[] } {
    return {
      cpu: dates.map((date, i) => ({
        date,
        value: 40 + Math.sin(i / 6) * 15 + Math.random() * 5,
      })),
      memory: dates.map((date, i) => ({
        date,
        value: 50 + Math.sin(i / 7) * 20 + Math.random() * 8,
      })),
      network: dates.map((date, i) => ({
        date,
        value: 30 + Math.sin(i / 5) * 10 + Math.random() * 4,
      })),
    };
  }

  async getExecutiveMetrics(timeRange: number = 30): Promise<any> {
    // Calculate executive metrics
    const reports = await this.getReports();
    const analytics = await this.getAnalytics(timeRange);
    
    // Calculate remediation velocity (issues fixed per week)
    const remediationVelocity = this.calculateRemediationVelocity(reports, timeRange);
    
    // Calculate ROI (simplified - would need actual cost data)
    const roiSavings = this.calculateROI(reports, timeRange);
    
    // Calculate risk score from analytics
    const riskScore = this.calculateRiskScore(analytics);
    
    return {
      riskScore,
      remediationVelocity: remediationVelocity.velocity,
      velocityTrend: remediationVelocity.trend,
      roiSavings
    };
  }

  async getRiskMetrics(timeRange: number = 30): Promise<any> {
    const analytics = await this.getAnalytics(timeRange);
    const reports = await this.getReports();
    
    // Filter reports by time range
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - timeRange);
    const filteredReports = reports.filter(
      (r: any) => r.generatedAt >= cutoffDate,
    );
    
    // Calculate risk metrics
    const days = timeRange;
    const dates = Array.from({ length: days }, (_, i) => {
      const date = new Date();
      date.setDate(date.getDate() - (days - i - 1));
      return date.toISOString().split('T')[0];
    });
    
    // Generate risk data from violation patterns
    const riskData = dates.map((date, i) => {
      const report = filteredReports.find(
        (r: any) => r.generatedAt.toISOString().split('T')[0] === date,
      );
      // Calculate risk from violations
      const violations = report?.data?.summary?.failedTests || 0;
      const total = report?.data?.summary?.totalTests || 1;
      const riskScore = (violations / total) * 100;
      return {
        date,
        value: Math.min(100, Math.max(0, riskScore))
      };
    });
    
    // Calculate current risk and trend
    const currentRisk = riskData.length > 0 ? riskData[riskData.length - 1].value : 50;
    const riskTrend = riskData.length > 1 
      ? currentRisk - riskData[0].value 
      : 0;
    
    // Risk distribution
    const riskDistribution = [
      { name: 'Critical', value: Math.round(currentRisk > 80 ? 10 : 5) },
      { name: 'High', value: Math.round(currentRisk > 60 ? 15 : 10) },
      { name: 'Medium', value: Math.round(currentRisk > 40 ? 30 : 25) },
      { name: 'Low', value: Math.round(100 - (currentRisk > 40 ? 30 : 25) - (currentRisk > 60 ? 15 : 10) - (currentRisk > 80 ? 10 : 5)) }
    ];
    
    // Top risks (from violation patterns)
    const topRisks = [
      { name: 'Unauthorized Data Access', severity: 'critical', score: Math.round(currentRisk + 20) },
      { name: 'Policy Violation', severity: 'high', score: Math.round(currentRisk + 10) },
      { name: 'Data Leakage Risk', severity: 'high', score: Math.round(currentRisk + 5) },
      { name: 'Compliance Drift', severity: 'medium', score: Math.round(currentRisk) }
    ];
    
    return {
      currentRisk: Math.round(currentRisk),
      riskTrend: Math.round(riskTrend * 10) / 10,
      riskData,
      riskDistribution,
      topRisks
    };
  }

  private calculateRemediationVelocity(reports: any[], timeRange: number): { velocity: number; trend: number } {
    // Simplified calculation - would need actual issue tracking
    const weeks = Math.ceil(timeRange / 7);
    const issuesFixed = reports.length * 2; // Mock: 2 issues per report
    const velocity = Math.round(issuesFixed / weeks);
    
    // Calculate trend (comparing first half vs second half)
    const midpoint = Math.floor(reports.length / 2);
    const firstHalf = reports.slice(0, midpoint).length * 2;
    const secondHalf = reports.slice(midpoint).length * 2;
    const trend = midpoint > 0 
      ? Math.round(((secondHalf - firstHalf) / firstHalf) * 100)
      : 0;
    
    return { velocity, trend };
  }

  private calculateROI(reports: any[], timeRange: number): number {
    // Simplified ROI calculation
    // Would need actual cost data for incidents prevented, time saved, etc.
    const baseSavings = 50000; // Base savings per month
    const reportsCount = reports.length;
    const months = timeRange / 30;
    return Math.round(baseSavings * months * (1 + reportsCount * 0.1));
  }

  private calculateRiskScore(analytics: any): number {
    // Calculate risk score from analytics data
    const violations = analytics.violationPatterns?.mostCommon || [];
    const totalViolations = violations.reduce((sum: number, v: any) => sum + v.value, 0);
    
    // Normalize to 0-100 scale (higher violations = higher risk)
    const maxExpectedViolations = 100;
    const riskScore = Math.min(100, (totalViolations / maxExpectedViolations) * 100);
    
    return Math.round(riskScore);
  }
}

