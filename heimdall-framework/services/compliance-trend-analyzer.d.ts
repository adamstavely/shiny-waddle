import { ComplianceScore } from '../core/types';
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
    trendSlope: number;
    averageScore: number;
    volatility: number;
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
    confidence: number;
    upperBound?: number;
    lowerBound?: number;
}
export interface SeasonalPattern {
    pattern: 'daily' | 'weekly' | 'monthly' | 'quarterly';
    description: string;
    impact: number;
}
export declare class ComplianceTrendAnalyzer {
    private historyDir;
    constructor(historyDir?: string);
    analyzeTrends(startDate: Date, endDate: Date, category?: string): Promise<TrendAnalysis>;
    storeScore(score: ComplianceScore): Promise<void>;
    private loadHistoricalScores;
    private prepareDataPoints;
    private calculateOverallTrend;
    private calculateTrendSlope;
    private calculateAverageScore;
    private calculateVolatility;
    private calculateCategoryTrends;
    private generatePredictions;
    private detectSeasonalPatterns;
    private detectWeeklyPattern;
    private detectMonthlyPattern;
    getTrendSummary(days?: number): Promise<{
        currentScore: number;
        previousScore: number;
        change: number;
        trend: 'improving' | 'declining' | 'stable';
    }>;
}
