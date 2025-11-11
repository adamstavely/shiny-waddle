/**
 * Compliance Trend Analysis Service
 * 
 * Analyzes compliance trends over time
 */

import { ComplianceScore, TestResult } from '../core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface TrendDataPoint {
  date: Date;
  score: number;
  category: string;
  metadata?: Record<string, any>;
}

export interface TrendAnalysis {
  period: {
    start: Date;
    end: Date;
  };
  overallTrend: 'improving' | 'declining' | 'stable';
  trendSlope: number; // Positive = improving, Negative = declining
  averageScore: number;
  volatility: number; // Standard deviation
  dataPoints: TrendDataPoint[];
  categoryTrends: Record<string, CategoryTrend>;
  predictions?: TrendPrediction[];
  seasonalPatterns?: SeasonalPattern[];
}

export interface CategoryTrend {
  category: string;
  trend: 'improving' | 'declining' | 'stable';
  slope: number;
  averageScore: number;
  volatility: number;
}

export interface TrendPrediction {
  date: Date;
  predictedScore: number;
  confidence: number; // 0-100
  upperBound?: number;
  lowerBound?: number;
}

export interface SeasonalPattern {
  pattern: 'daily' | 'weekly' | 'monthly' | 'quarterly';
  description: string;
  impact: number; // -100 to 100
}

export class ComplianceTrendAnalyzer {
  private historyDir: string;

  constructor(historyDir: string = './reports/history') {
    this.historyDir = historyDir;
  }

  /**
   * Analyze trends from historical data
   */
  async analyzeTrends(
    startDate: Date,
    endDate: Date,
    category?: string
  ): Promise<TrendAnalysis> {
    const historicalScores = await this.loadHistoricalScores(startDate, endDate);
    const dataPoints = this.prepareDataPoints(historicalScores, category);

    const overallTrend = this.calculateOverallTrend(dataPoints);
    const trendSlope = this.calculateTrendSlope(dataPoints);
    const averageScore = this.calculateAverageScore(dataPoints);
    const volatility = this.calculateVolatility(dataPoints);
    const categoryTrends = this.calculateCategoryTrends(historicalScores);
    const predictions = this.generatePredictions(dataPoints);
    const seasonalPatterns = this.detectSeasonalPatterns(dataPoints);

    return {
      period: { start: startDate, end: endDate },
      overallTrend,
      trendSlope,
      averageScore,
      volatility,
      dataPoints,
      categoryTrends,
      predictions,
      seasonalPatterns,
    };
  }

  /**
   * Store compliance score for trend analysis
   */
  async storeScore(score: ComplianceScore): Promise<void> {
    await fs.mkdir(this.historyDir, { recursive: true });
    const timestamp = score.lastUpdated.toISOString().replace(/[:.]/g, '-');
    const filePath = path.join(this.historyDir, `${timestamp}.json`);
    await fs.writeFile(filePath, JSON.stringify(score, null, 2));
  }

  /**
   * Load historical scores
   */
  private async loadHistoricalScores(
    startDate: Date,
    endDate: Date
  ): Promise<ComplianceScore[]> {
    try {
      const files = await fs.readdir(this.historyDir);
      const scores: ComplianceScore[] = [];

      for (const file of files) {
        if (!file.endsWith('.json')) continue;

        const filePath = path.join(this.historyDir, file);
        const content = await fs.readFile(filePath, 'utf-8');
        const score: ComplianceScore = JSON.parse(content);

        const scoreDate = new Date(score.lastUpdated);
        if (scoreDate >= startDate && scoreDate <= endDate) {
          scores.push(score);
        }
      }

      return scores.sort((a, b) => 
        a.lastUpdated.getTime() - b.lastUpdated.getTime()
      );
    } catch (error) {
      return [];
    }
  }

  /**
   * Prepare data points from scores
   */
  private prepareDataPoints(
    scores: ComplianceScore[],
    category?: string
  ): TrendDataPoint[] {
    if (category) {
      return scores.map(score => ({
        date: score.lastUpdated,
        score: score.scoresByCategory[category as keyof typeof score.scoresByCategory] || 0,
        category,
        metadata: {
          application: score.application,
          team: score.team,
        },
      }));
    }

    return scores.map(score => ({
      date: score.lastUpdated,
      score: score.overallScore,
      category: 'overall',
      metadata: {
        application: score.application,
        team: score.team,
      },
    }));
  }

  /**
   * Calculate overall trend
   */
  private calculateOverallTrend(dataPoints: TrendDataPoint[]): 'improving' | 'declining' | 'stable' {
    if (dataPoints.length < 2) return 'stable';

    const slope = this.calculateTrendSlope(dataPoints);
    const threshold = 2; // Minimum change to be considered a trend

    if (slope > threshold) return 'improving';
    if (slope < -threshold) return 'declining';
    return 'stable';
  }

  /**
   * Calculate trend slope using linear regression
   */
  private calculateTrendSlope(dataPoints: TrendDataPoint[]): number {
    if (dataPoints.length < 2) return 0;

    const n = dataPoints.length;
    let sumX = 0;
    let sumY = 0;
    let sumXY = 0;
    let sumX2 = 0;

    for (const point of dataPoints) {
      const x = point.date.getTime();
      const y = point.score;
      sumX += x;
      sumY += y;
      sumXY += x * y;
      sumX2 += x * x;
    }

    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);
    return slope * (1000 * 60 * 60 * 24); // Convert to score per day
  }

  /**
   * Calculate average score
   */
  private calculateAverageScore(dataPoints: TrendDataPoint[]): number {
    if (dataPoints.length === 0) return 0;
    const sum = dataPoints.reduce((acc, point) => acc + point.score, 0);
    return sum / dataPoints.length;
  }

  /**
   * Calculate volatility (standard deviation)
   */
  private calculateVolatility(dataPoints: TrendDataPoint[]): number {
    if (dataPoints.length === 0) return 0;

    const average = this.calculateAverageScore(dataPoints);
    const variance = dataPoints.reduce((acc, point) => {
      return acc + Math.pow(point.score - average, 2);
    }, 0) / dataPoints.length;

    return Math.sqrt(variance);
  }

  /**
   * Calculate trends by category
   */
  private calculateCategoryTrends(
    scores: ComplianceScore[]
  ): Record<string, CategoryTrend> {
    const categories = ['accessControl', 'dataBehavior', 'contracts', 'datasetHealth'];
    const trends: Record<string, CategoryTrend> = {};

    for (const category of categories) {
      const dataPoints = this.prepareDataPoints(scores, category);
      const trend = this.calculateOverallTrend(dataPoints);
      const slope = this.calculateTrendSlope(dataPoints);
      const average = this.calculateAverageScore(dataPoints);
      const volatility = this.calculateVolatility(dataPoints);

      trends[category] = {
        category,
        trend,
        slope,
        averageScore: average,
        volatility,
      };
    }

    return trends;
  }

  /**
   * Generate predictions using simple linear regression
   */
  private generatePredictions(
    dataPoints: TrendDataPoint[],
    daysAhead: number = 30
  ): TrendPrediction[] {
    if (dataPoints.length < 2) return [];

    const slope = this.calculateTrendSlope(dataPoints);
    const average = this.calculateAverageScore(dataPoints);
    const lastPoint = dataPoints[dataPoints.length - 1];
    const predictions: TrendPrediction[] = [];

    for (let i = 1; i <= daysAhead; i++) {
      const futureDate = new Date(lastPoint.date);
      futureDate.setDate(futureDate.getDate() + i);

      const daysFromLast = i;
      const predictedScore = lastPoint.score + (slope * daysFromLast);
      
      // Confidence decreases over time
      const confidence = Math.max(50, 100 - (i * 2));
      
      // Calculate bounds (simplified)
      const volatility = this.calculateVolatility(dataPoints);
      const upperBound = predictedScore + (volatility * 1.96); // 95% confidence
      const lowerBound = predictedScore - (volatility * 1.96);

      predictions.push({
        date: futureDate,
        predictedScore: Math.max(0, Math.min(100, predictedScore)),
        confidence,
        upperBound: Math.max(0, Math.min(100, upperBound)),
        lowerBound: Math.max(0, Math.min(100, lowerBound)),
      });
    }

    return predictions;
  }

  /**
   * Detect seasonal patterns
   */
  private detectSeasonalPatterns(
    dataPoints: TrendDataPoint[]
  ): SeasonalPattern[] {
    if (dataPoints.length < 7) return [];

    const patterns: SeasonalPattern[] = [];

    // Check for weekly patterns
    const weeklyPattern = this.detectWeeklyPattern(dataPoints);
    if (weeklyPattern) {
      patterns.push(weeklyPattern);
    }

    // Check for monthly patterns
    const monthlyPattern = this.detectMonthlyPattern(dataPoints);
    if (monthlyPattern) {
      patterns.push(monthlyPattern);
    }

    return patterns;
  }

  /**
   * Detect weekly patterns
   */
  private detectWeeklyPattern(
    dataPoints: TrendDataPoint[]
  ): SeasonalPattern | null {
    // Group by day of week
    const byDayOfWeek: Record<number, number[]> = {};
    
    for (const point of dataPoints) {
      const dayOfWeek = point.date.getDay();
      if (!byDayOfWeek[dayOfWeek]) {
        byDayOfWeek[dayOfWeek] = [];
      }
      byDayOfWeek[dayOfWeek].push(point.score);
    }

    // Calculate average for each day
    const averages: Record<number, number> = {};
    for (const [day, scores] of Object.entries(byDayOfWeek)) {
      averages[parseInt(day)] = scores.reduce((a, b) => a + b, 0) / scores.length;
    }

    // Check for significant variation
    const overallAvg = Object.values(averages).reduce((a, b) => a + b, 0) / 7;
    const maxDeviation = Math.max(...Object.values(averages).map(avg => Math.abs(avg - overallAvg)));

    if (maxDeviation > 5) {
      return {
        pattern: 'weekly',
        description: 'Weekly compliance score variation detected',
        impact: maxDeviation,
      };
    }

    return null;
  }

  /**
   * Detect monthly patterns
   */
  private detectMonthlyPattern(
    dataPoints: TrendDataPoint[]
  ): SeasonalPattern | null {
    // Group by day of month
    const byDayOfMonth: Record<number, number[]> = {};
    
    for (const point of dataPoints) {
      const dayOfMonth = point.date.getDate();
      if (!byDayOfMonth[dayOfMonth]) {
        byDayOfMonth[dayOfMonth] = [];
      }
      byDayOfMonth[dayOfMonth].push(point.score);
    }

    // Similar analysis as weekly
    const averages: Record<number, number> = {};
    for (const [day, scores] of Object.entries(byDayOfMonth)) {
      if (scores.length > 0) {
        averages[parseInt(day)] = scores.reduce((a, b) => a + b, 0) / scores.length;
      }
    }

    const overallAvg = Object.values(averages).reduce((a, b) => a + b, 0) / Object.keys(averages).length;
    const maxDeviation = Math.max(...Object.values(averages).map(avg => Math.abs(avg - overallAvg)));

    if (maxDeviation > 5) {
      return {
        pattern: 'monthly',
        description: 'Monthly compliance score variation detected',
        impact: maxDeviation,
      };
    }

    return null;
  }

  /**
   * Get trend summary
   */
  async getTrendSummary(days: number = 30): Promise<{
    currentScore: number;
    previousScore: number;
    change: number;
    trend: 'improving' | 'declining' | 'stable';
  }> {
    const endDate = new Date();
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const analysis = await this.analyzeTrends(startDate, endDate);

    if (analysis.dataPoints.length < 2) {
      return {
        currentScore: 0,
        previousScore: 0,
        change: 0,
        trend: 'stable',
      };
    }

    const currentScore = analysis.dataPoints[analysis.dataPoints.length - 1].score;
    const previousScore = analysis.dataPoints[0].score;
    const change = currentScore - previousScore;

    return {
      currentScore,
      previousScore,
      change,
      trend: analysis.overallTrend,
    };
  }
}

