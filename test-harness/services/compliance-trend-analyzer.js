"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComplianceTrendAnalyzer = void 0;
const fs = require("fs/promises");
const path = require("path");
class ComplianceTrendAnalyzer {
    constructor(historyDir = './reports/history') {
        this.historyDir = historyDir;
    }
    async analyzeTrends(startDate, endDate, category) {
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
    async storeScore(score) {
        await fs.mkdir(this.historyDir, { recursive: true });
        const timestamp = score.lastUpdated.toISOString().replace(/[:.]/g, '-');
        const filePath = path.join(this.historyDir, `${timestamp}.json`);
        await fs.writeFile(filePath, JSON.stringify(score, null, 2));
    }
    async loadHistoricalScores(startDate, endDate) {
        try {
            const files = await fs.readdir(this.historyDir);
            const scores = [];
            for (const file of files) {
                if (!file.endsWith('.json'))
                    continue;
                const filePath = path.join(this.historyDir, file);
                const content = await fs.readFile(filePath, 'utf-8');
                const score = JSON.parse(content);
                const scoreDate = new Date(score.lastUpdated);
                if (scoreDate >= startDate && scoreDate <= endDate) {
                    scores.push(score);
                }
            }
            return scores.sort((a, b) => a.lastUpdated.getTime() - b.lastUpdated.getTime());
        }
        catch (error) {
            return [];
        }
    }
    prepareDataPoints(scores, category) {
        if (category) {
            return scores.map(score => ({
                date: score.lastUpdated,
                score: score.scoresByCategory[category] || 0,
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
    calculateOverallTrend(dataPoints) {
        if (dataPoints.length < 2)
            return 'stable';
        const slope = this.calculateTrendSlope(dataPoints);
        const threshold = 2;
        if (slope > threshold)
            return 'improving';
        if (slope < -threshold)
            return 'declining';
        return 'stable';
    }
    calculateTrendSlope(dataPoints) {
        if (dataPoints.length < 2)
            return 0;
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
        return slope * (1000 * 60 * 60 * 24);
    }
    calculateAverageScore(dataPoints) {
        if (dataPoints.length === 0)
            return 0;
        const sum = dataPoints.reduce((acc, point) => acc + point.score, 0);
        return sum / dataPoints.length;
    }
    calculateVolatility(dataPoints) {
        if (dataPoints.length === 0)
            return 0;
        const average = this.calculateAverageScore(dataPoints);
        const variance = dataPoints.reduce((acc, point) => {
            return acc + Math.pow(point.score - average, 2);
        }, 0) / dataPoints.length;
        return Math.sqrt(variance);
    }
    calculateCategoryTrends(scores) {
        const categories = ['accessControl', 'dataBehavior', 'contracts', 'datasetHealth'];
        const trends = {};
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
    generatePredictions(dataPoints, daysAhead = 30) {
        if (dataPoints.length < 2)
            return [];
        const slope = this.calculateTrendSlope(dataPoints);
        const average = this.calculateAverageScore(dataPoints);
        const lastPoint = dataPoints[dataPoints.length - 1];
        const predictions = [];
        for (let i = 1; i <= daysAhead; i++) {
            const futureDate = new Date(lastPoint.date);
            futureDate.setDate(futureDate.getDate() + i);
            const daysFromLast = i;
            const predictedScore = lastPoint.score + (slope * daysFromLast);
            const confidence = Math.max(50, 100 - (i * 2));
            const volatility = this.calculateVolatility(dataPoints);
            const upperBound = predictedScore + (volatility * 1.96);
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
    detectSeasonalPatterns(dataPoints) {
        if (dataPoints.length < 7)
            return [];
        const patterns = [];
        const weeklyPattern = this.detectWeeklyPattern(dataPoints);
        if (weeklyPattern) {
            patterns.push(weeklyPattern);
        }
        const monthlyPattern = this.detectMonthlyPattern(dataPoints);
        if (monthlyPattern) {
            patterns.push(monthlyPattern);
        }
        return patterns;
    }
    detectWeeklyPattern(dataPoints) {
        const byDayOfWeek = {};
        for (const point of dataPoints) {
            const dayOfWeek = point.date.getDay();
            if (!byDayOfWeek[dayOfWeek]) {
                byDayOfWeek[dayOfWeek] = [];
            }
            byDayOfWeek[dayOfWeek].push(point.score);
        }
        const averages = {};
        for (const [day, scores] of Object.entries(byDayOfWeek)) {
            averages[parseInt(day)] = scores.reduce((a, b) => a + b, 0) / scores.length;
        }
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
    detectMonthlyPattern(dataPoints) {
        const byDayOfMonth = {};
        for (const point of dataPoints) {
            const dayOfMonth = point.date.getDate();
            if (!byDayOfMonth[dayOfMonth]) {
                byDayOfMonth[dayOfMonth] = [];
            }
            byDayOfMonth[dayOfMonth].push(point.score);
        }
        const averages = {};
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
    async getTrendSummary(days = 30) {
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
exports.ComplianceTrendAnalyzer = ComplianceTrendAnalyzer;
//# sourceMappingURL=compliance-trend-analyzer.js.map