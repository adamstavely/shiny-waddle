import { Injectable, Logger } from '@nestjs/common';
import { TestResultsService } from '../../test-results/test-results.service';
import { TestResultEntity } from '../../test-results/entities/test-result.entity';

export interface RiskHeatmapData {
  applicationId: string;
  applicationName: string;
  riskScore: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  testConfigurationType: string;
  timestamp: Date;
}

export interface RiskTrend {
  period: string; // ISO date string or period identifier
  averageRiskScore: number;
  totalRisks: number;
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  trend: 'increasing' | 'decreasing' | 'stable';
  changePercentage: number;
}

export interface AdvancedRiskScore extends RiskScore {
  heatmapData: RiskHeatmapData;
  trend: RiskTrend;
  priorityRank: number;
}

export interface RiskScore {
  testResultId: string;
  applicationId: string;
  applicationName: string;
  testConfigurationId: string;
  testConfigurationName: string;
  testConfigurationType: string;
  riskScore: number; // 0-100
  severity: 'critical' | 'high' | 'medium' | 'low';
  businessImpact: number; // 0-100
  priority: number; // 0-100, higher = more urgent
  factors: RiskFactor[];
  recommendations: string[];
  timestamp: Date;
}

export interface RiskFactor {
  name: string;
  impact: number; // 0-100
  description: string;
}

@Injectable()
export class EnhancedRiskScoringService {
  private readonly logger = new Logger(EnhancedRiskScoringService.name);
  private historicalScores: Map<string, Array<{ timestamp: Date; score: number }>> = new Map();

  constructor(private readonly testResultsService: TestResultsService) {}

  /**
   * Calculate risk score for a test result
   */
  async calculateRiskScore(testResult: TestResultEntity): Promise<AdvancedRiskScore> {
    const baseScore = this.calculateBaseRiskScore(testResult);
    const factors = this.identifyRiskFactors(testResult);
    const businessImpact = this.calculateBusinessImpact(testResult, factors);
    const priority = this.calculatePriority(baseScore, businessImpact, testResult);
    const recommendations = this.generateRecommendations(testResult, factors);

    // Get trend data
    const trend = await this.calculateTrend(testResult.applicationId, testResult.testConfigurationId);

    // Create heatmap data
    const heatmapData: RiskHeatmapData = {
      applicationId: testResult.applicationId,
      applicationName: testResult.applicationName,
      riskScore: baseScore,
      severity: this.determineSeverity(baseScore),
      testConfigurationType: testResult.testConfigurationType,
      timestamp: testResult.timestamp,
    };

    // Store historical score for trend analysis
    this.storeHistoricalScore(testResult.id, baseScore);

    return {
      testResultId: testResult.id,
      applicationId: testResult.applicationId,
      applicationName: testResult.applicationName,
      testConfigurationId: testResult.testConfigurationId,
      testConfigurationName: testResult.testConfigurationName,
      testConfigurationType: testResult.testConfigurationType,
      riskScore: baseScore,
      severity: this.determineSeverity(baseScore),
      businessImpact,
      priority,
      factors,
      recommendations,
      timestamp: testResult.timestamp,
      heatmapData,
      trend,
      priorityRank: 0, // Will be set when prioritizing multiple scores
    };
  }

  /**
   * Calculate risk scores for multiple test results
   */
  async calculateRiskScores(testResults: TestResultEntity[]): Promise<AdvancedRiskScore[]> {
    const scores = await Promise.all(
      testResults.map(result => this.calculateRiskScore(result))
    );

    // Assign priority ranks
    return this.assignPriorityRanks(scores);
  }

  /**
   * Generate heatmap data for visualization
   */
  async generateHeatmapData(options?: {
    applicationId?: string;
    startDate?: Date;
    endDate?: Date;
    groupBy?: 'application' | 'testType' | 'severity';
  }): Promise<RiskHeatmapData[]> {
    const testResults = await this.testResultsService.query({
      applicationId: options?.applicationId,
      startDate: options?.startDate,
      endDate: options?.endDate,
    });

    const heatmapData: RiskHeatmapData[] = [];

    for (const result of testResults) {
      if (!result.passed) {
        const score = await this.calculateRiskScore(result);
        heatmapData.push(score.heatmapData);
      }
    }

    return heatmapData;
  }

  /**
   * Calculate risk trends over time
   */
  async calculateTrends(options?: {
    applicationId?: string;
    testConfigurationId?: string;
    period?: 'day' | 'week' | 'month';
    startDate?: Date;
    endDate?: Date;
  }): Promise<RiskTrend[]> {
    const period = options?.period || 'day';
    const testResults = await this.testResultsService.query({
      applicationId: options?.applicationId,
      testConfigurationId: options?.testConfigurationId,
      startDate: options?.startDate,
      endDate: options?.endDate,
    });

    // Group results by period
    const grouped = this.groupByPeriod(testResults, period);

    const trends: RiskTrend[] = [];
    let previousTrend: RiskTrend | null = null;

    for (const [periodKey, results] of Object.entries(grouped)) {
      const failedResults = results.filter(r => !r.passed);
      const scores = await Promise.all(
        failedResults.map(r => this.calculateRiskScore(r))
      );

      const averageScore = scores.length > 0
        ? scores.reduce((sum, s) => sum + s.riskScore, 0) / scores.length
        : 0;

      const bySeverity = {
        critical: scores.filter(s => s.severity === 'critical').length,
        high: scores.filter(s => s.severity === 'high').length,
        medium: scores.filter(s => s.severity === 'medium').length,
        low: scores.filter(s => s.severity === 'low').length,
      };

      let trend: 'increasing' | 'decreasing' | 'stable' = 'stable';
      let changePercentage = 0;

      if (previousTrend) {
        changePercentage = ((averageScore - previousTrend.averageRiskScore) / previousTrend.averageRiskScore) * 100;
        if (changePercentage > 5) {
          trend = 'increasing';
        } else if (changePercentage < -5) {
          trend = 'decreasing';
        }
      }

      const riskTrend: RiskTrend = {
        period: periodKey,
        averageRiskScore: averageScore,
        totalRisks: scores.length,
        bySeverity,
        trend,
        changePercentage,
      };

      trends.push(riskTrend);
      previousTrend = riskTrend;
    }

    return trends.sort((a, b) => a.period.localeCompare(b.period));
  }

  /**
   * Advanced prioritization with multiple factors
   */
  prioritizeRisks(scores: AdvancedRiskScore[]): AdvancedRiskScore[] {
    return scores
      .map(score => ({
        ...score,
        priorityRank: this.calculateAdvancedPriority(score),
      }))
      .sort((a, b) => {
        // Sort by priority rank (descending)
        if (b.priorityRank !== a.priorityRank) {
          return b.priorityRank - a.priorityRank;
        }
        // Then by risk score
        if (b.riskScore !== a.riskScore) {
          return b.riskScore - a.riskScore;
        }
        // Then by severity
        const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
        return severityOrder[b.severity] - severityOrder[a.severity];
      })
      .map((score, index) => ({
        ...score,
        priorityRank: index + 1,
      }));
  }

  /**
   * Calculate base risk score
   */
  private calculateBaseRiskScore(result: TestResultEntity): number {
    if (result.passed) {
      return 0;
    }

    let score = 50; // Base score for failed tests

    // Adjust based on test configuration type
    const typeWeights: Record<string, number> = {
      'rls-cls': 30,
      'network-policy': 25,
      'dlp': 35,
      'api-gateway': 30,
      'api-security': 40,
      'data-pipeline': 20,
    };
    score += typeWeights[result.testConfigurationType] || 20;

    // Adjust based on error severity
    if (result.error) {
      score += 20;
      if (result.error.type?.toLowerCase().includes('critical')) {
        score += 10;
      }
    }

    // Adjust based on remediation status
    if (result.remediation) {
      if (result.remediation.status === 'not-started') {
        score += 15;
      } else if (result.remediation.status === 'in-progress') {
        score += 5;
      }
    }

    // Adjust based on risk acceptance
    if (result.riskAcceptance?.accepted) {
      score -= 10; // Accepted risks are lower priority
    }

    return Math.min(100, Math.max(0, score));
  }

  /**
   * Identify risk factors
   */
  private identifyRiskFactors(result: TestResultEntity): RiskFactor[] {
    const factors: RiskFactor[] = [];

    // Test type factor
    factors.push({
      name: 'Test Type',
      impact: 20,
      description: `${result.testConfigurationType} test failure`,
    });

    // Error factor
    if (result.error) {
      factors.push({
        name: 'Error Severity',
        impact: 30,
        description: result.error.message || 'Test error occurred',
      });
    }

    // Remediation status factor
    if (result.remediation) {
      if (result.remediation.status === 'not-started') {
        factors.push({
          name: 'Remediation Status',
          impact: 25,
          description: 'Remediation not started',
        });
      }
    }

    // Age factor (how long has this been failing?)
    const ageInDays = (Date.now() - result.timestamp.getTime()) / (1000 * 60 * 60 * 24);
    if (ageInDays > 30) {
      factors.push({
        name: 'Age',
        impact: 15,
        description: `Issue open for ${Math.round(ageInDays)} days`,
      });
    }

    return factors;
  }

  /**
   * Calculate business impact
   */
  private calculateBusinessImpact(result: TestResultEntity, factors: RiskFactor[]): number {
    let impact = 0;

    // Test type impact
    const testTypeFactor = factors.find(f => f.name === 'Test Type');
    if (testTypeFactor) {
      impact += testTypeFactor.impact * 0.4;
    }

    // Error impact
    const errorFactor = factors.find(f => f.name === 'Error Severity');
    if (errorFactor) {
      impact += errorFactor.impact * 0.3;
    }

    // Remediation impact
    const remediationFactor = factors.find(f => f.name === 'Remediation Status');
    if (remediationFactor) {
      impact += remediationFactor.impact * 0.3;
    }

    return Math.min(100, impact);
  }

  /**
   * Calculate priority with advanced factors
   */
  private calculatePriority(
    riskScore: number,
    businessImpact: number,
    result: TestResultEntity
  ): number {
    let priority = (riskScore * 0.6) + (businessImpact * 0.4);

    // Boost priority for critical errors
    if (result.error?.type?.toLowerCase().includes('critical')) {
      priority += 20;
    }

    // Boost priority for unaddressed issues
    if (!result.remediation || result.remediation.status === 'not-started') {
      priority += 15;
    }

    // Boost priority for expired risk acceptances
    if (result.riskAcceptance?.accepted && result.riskAcceptance.expirationDate) {
      if (new Date() > result.riskAcceptance.expirationDate) {
        priority += 25;
      }
    }

    return Math.min(100, priority);
  }

  /**
   * Calculate advanced priority rank
   */
  private calculateAdvancedPriority(score: AdvancedRiskScore): number {
    let rank = score.priority;

    // Boost for increasing trends
    if (score.trend.trend === 'increasing') {
      rank += 10;
    }

    // Boost for critical severity
    if (score.severity === 'critical') {
      rank += 15;
    }

    // Boost for high business impact
    if (score.businessImpact > 70) {
      rank += 10;
    }

    return Math.min(100, rank);
  }

  /**
   * Determine severity
   */
  private determineSeverity(riskScore: number): 'critical' | 'high' | 'medium' | 'low' {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    return 'low';
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(result: TestResultEntity, factors: RiskFactor[]): string[] {
    const recommendations: string[] = [];

    if (result.error) {
      recommendations.push(`Address error: ${result.error.message}`);
    }

    if (!result.remediation || result.remediation.status === 'not-started') {
      recommendations.push('Start remediation process');
    }

    if (result.riskAcceptance?.accepted && result.riskAcceptance.expirationDate) {
      if (new Date() > result.riskAcceptance.expirationDate) {
        recommendations.push('Risk acceptance has expired - review required');
      }
    }

    const severity = this.determineSeverity(
      factors.reduce((sum, f) => sum + f.impact, 0)
    );

    if (severity === 'critical' || severity === 'high') {
      recommendations.push('Immediate remediation required');
    }

    return recommendations;
  }

  /**
   * Calculate trend for a specific application/config
   */
  private async calculateTrend(
    applicationId: string,
    testConfigurationId: string
  ): Promise<RiskTrend> {
    const testResults = await this.testResultsService.query({
      applicationId,
      testConfigurationId,
      startDate: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // Last 30 days
    });

    const failedResults = testResults.filter(r => !r.passed);
    if (failedResults.length === 0) {
      return {
        period: '30days',
        averageRiskScore: 0,
        totalRisks: 0,
        bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
        trend: 'stable',
        changePercentage: 0,
      };
    }

    const scores = failedResults.map(r => this.calculateBaseRiskScore(r));
    const averageScore = scores.reduce((sum, s) => sum + s, 0) / scores.length;

    const severities = failedResults.map(r => this.determineSeverity(this.calculateBaseRiskScore(r)));
    const bySeverity = {
      critical: severities.filter(s => s === 'critical').length,
      high: severities.filter(s => s === 'high').length,
      medium: severities.filter(s => s === 'medium').length,
      low: severities.filter(s => s === 'low').length,
    };

    return {
      period: '30days',
      averageRiskScore: averageScore,
      totalRisks: failedResults.length,
      bySeverity,
      trend: 'stable', // Would need historical data for accurate trend
      changePercentage: 0,
    };
  }

  /**
   * Group test results by time period
   */
  private groupByPeriod(
    results: TestResultEntity[],
    period: 'day' | 'week' | 'month'
  ): Record<string, TestResultEntity[]> {
    const grouped: Record<string, TestResultEntity[]> = {};

    for (const result of results) {
      let key: string;
      const date = new Date(result.timestamp);

      switch (period) {
        case 'day':
          key = date.toISOString().split('T')[0];
          break;
        case 'week':
          const weekStart = new Date(date);
          weekStart.setDate(date.getDate() - date.getDay());
          key = weekStart.toISOString().split('T')[0];
          break;
        case 'month':
          key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
          break;
      }

      if (!grouped[key]) {
        grouped[key] = [];
      }
      grouped[key].push(result);
    }

    return grouped;
  }

  /**
   * Store historical score for trend analysis
   */
  private storeHistoricalScore(testResultId: string, score: number): void {
    if (!this.historicalScores.has(testResultId)) {
      this.historicalScores.set(testResultId, []);
    }

    const history = this.historicalScores.get(testResultId)!;
    history.push({
      timestamp: new Date(),
      score,
    });

    // Keep only last 100 entries per result
    if (history.length > 100) {
      history.shift();
    }
  }

  /**
   * Assign priority ranks to scores
   */
  private assignPriorityRanks(scores: AdvancedRiskScore[]): AdvancedRiskScore[] {
    const prioritized = this.prioritizeRisks(scores);
    return prioritized.map((score, index) => ({
      ...score,
      priorityRank: index + 1,
    }));
  }
}

