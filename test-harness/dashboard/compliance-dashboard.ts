/**
 * Compliance Dashboard Service
 * 
 * Provides dashboard functionality to show compliance scores by
 * application, team, and dataset
 */

import { ComplianceScore, TestResult } from '../core/types';
import { ComplianceReporter } from '../services/compliance-reporter';

export interface DashboardData {
  overallCompliance: number;
  scoresByApplication: Record<string, ComplianceScore>;
  scoresByTeam: Record<string, ComplianceScore>;
  scoresByDataset: Record<string, ComplianceScore>;
  recentTestResults: TestResult[];
  trends: TrendData[];
}

export interface TrendData {
  date: Date;
  score: number;
  category: string;
}

export class ComplianceDashboard {
  private reporter: ComplianceReporter;
  private historicalData: ComplianceScore[] = [];

  constructor(reporter: ComplianceReporter) {
    this.reporter = reporter;
  }

  /**
   * Generate dashboard data
   */
  async generateDashboardData(results: TestResult[]): Promise<DashboardData> {
    const scores = this.reporter.calculateScores(results);

    // Group results by application, team, dataset
    const scoresByApplication = this.calculateScoresByApplication(results);
    const scoresByTeam = this.calculateScoresByTeam(results);
    const scoresByDataset = this.calculateScoresByDataset(results);

    // Get recent test results
    const recentTestResults = results
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
      .slice(0, 50);

    // Calculate trends
    const trends = this.calculateTrends();

    return {
      overallCompliance: scores.overall,
      scoresByApplication,
      scoresByTeam,
      scoresByDataset,
      recentTestResults,
      trends,
    };
  }

  /**
   * Calculate scores by application
   */
  private calculateScoresByApplication(
    results: TestResult[]
  ): Record<string, ComplianceScore> {
    const applicationGroups: Record<string, TestResult[]> = {};

    for (const result of results) {
      const application = this.extractApplication(result) || 'unknown';
      if (!applicationGroups[application]) {
        applicationGroups[application] = [];
      }
      applicationGroups[application].push(result);
    }

    const scores: Record<string, ComplianceScore> = {};

    for (const [application, appResults] of Object.entries(applicationGroups)) {
      const appScores = this.reporter.calculateScores(appResults);
      scores[application] = {
        application,
        team: this.extractTeam(appResults[0]) || 'unknown',
        overallScore: appScores.overall,
        scoresByCategory: {
          accessControl: appScores.byCategory['access-control'] || 100,
          dataBehavior: appScores.byCategory['data-behavior'] || 100,
          contracts: appScores.byCategory['contract'] || 100,
          datasetHealth: appScores.byCategory['dataset-health'] || 100,
        },
        testResults: appResults,
        lastUpdated: new Date(),
      };
    }

    return scores;
  }

  /**
   * Calculate scores by team
   */
  private calculateScoresByTeam(results: TestResult[]): Record<string, ComplianceScore> {
    const teamGroups: Record<string, TestResult[]> = {};

    for (const result of results) {
      const team = this.extractTeam(result) || 'unknown';
      if (!teamGroups[team]) {
        teamGroups[team] = [];
      }
      teamGroups[team].push(result);
    }

    const scores: Record<string, ComplianceScore> = {};

    for (const [team, teamResults] of Object.entries(teamGroups)) {
      const teamScores = this.reporter.calculateScores(teamResults);
      scores[team] = {
        application: this.extractApplication(teamResults[0]) || 'unknown',
        team,
        overallScore: teamScores.overall,
        scoresByCategory: {
          accessControl: teamScores.byCategory['access-control'] || 100,
          dataBehavior: teamScores.byCategory['data-behavior'] || 100,
          contracts: teamScores.byCategory['contract'] || 100,
          datasetHealth: teamScores.byCategory['dataset-health'] || 100,
        },
        testResults: teamResults,
        lastUpdated: new Date(),
      };
    }

    return scores;
  }

  /**
   * Calculate scores by dataset
   */
  private calculateScoresByDataset(results: TestResult[]): Record<string, ComplianceScore> {
    const datasetGroups: Record<string, TestResult[]> = {};

    for (const result of results) {
      if (result.testType === 'dataset-health') {
        const dataset = this.extractDataset(result) || 'unknown';
        if (!datasetGroups[dataset]) {
          datasetGroups[dataset] = [];
        }
        datasetGroups[dataset].push(result);
      }
    }

    const scores: Record<string, ComplianceScore> = {};

    for (const [dataset, datasetResults] of Object.entries(datasetGroups)) {
      const datasetScores = this.reporter.calculateScores(datasetResults);
      scores[dataset] = {
        application: this.extractApplication(datasetResults[0]) || 'unknown',
        team: this.extractTeam(datasetResults[0]) || 'unknown',
        overallScore: datasetScores.overall,
        scoresByCategory: {
          accessControl: 100,
          dataBehavior: 100,
          contracts: 100,
          datasetHealth: datasetScores.overall,
        },
        testResults: datasetResults,
        lastUpdated: new Date(),
      };
    }

    return scores;
  }

  /**
   * Calculate trends over time
   */
  private calculateTrends(): TrendData[] {
    // Would use historical data to calculate trends
    // For now, return empty array
    return [];
  }

  /**
   * Extract application from result
   */
  private extractApplication(result: TestResult): string | null {
    return result.details?.application || null;
  }

  /**
   * Extract team from result
   */
  private extractTeam(result: TestResult): string | null {
    return result.details?.team || null;
  }

  /**
   * Extract dataset from result
   */
  private extractDataset(result: TestResult): string | null {
    return result.details?.datasetName || null;
  }

  /**
   * Store historical score
   */
  storeHistoricalScore(score: ComplianceScore): void {
    this.historicalData.push(score);
  }

  /**
   * Get historical scores
   */
  getHistoricalScores(): ComplianceScore[] {
    return this.historicalData;
  }
}

