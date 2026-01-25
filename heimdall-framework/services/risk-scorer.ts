/**
 * Risk Scoring & Prioritization Service
 * 
 * Scores and prioritizes compliance risks
 */

import { TestResult } from '../core/types';

export interface RiskScore {
  testResult: TestResult;
  riskScore: number; // 0-100
  severity: 'critical' | 'high' | 'medium' | 'low';
  businessImpact: number; // 0-100
  priority: number; // 0-100, higher = more urgent
  factors: RiskFactor[];
  recommendations: string[];
}

export interface RiskFactor {
  name: string;
  impact: number; // 0-100
  description: string;
}

export interface RiskScoringConfig {
  weights: {
    testType: Record<string, number>;
    dataSensitivity: Record<string, number>;
    userRole: Record<string, number>;
    violationType: Record<string, number>;
  };
  thresholds: {
    critical: number;
    high: number;
    medium: number;
  };
}

export class RiskScorer {
  private config: RiskScoringConfig;

  constructor(config?: Partial<RiskScoringConfig>) {
    this.config = {
      weights: {
        testType: {
          'access-control': 30,
          'data-behavior': 25,
          'contract': 20,
          'dataset-health': 15,
        },
        dataSensitivity: {
          'restricted': 40,
          'confidential': 30,
          'internal': 20,
          'public': 10,
        },
        userRole: {
          'admin': 10,
          'researcher': 20,
          'analyst': 25,
          'viewer': 30,
        },
        violationType: {
          'sql-injection': 50,
          'privilege-escalation': 45,
          'data-leakage': 40,
          'pii-exposure': 35,
          'over-broad-query': 30,
          'missing-filter': 25,
          'disallowed-join': 20,
          'policy-violation': 15,
        },
      },
      thresholds: {
        critical: 80,
        high: 60,
        medium: 40,
      },
      ...config,
    };
  }

  /**
   * Score a test result
   */
  scoreTestResult(result: TestResult): RiskScore {
    if (result.passed) {
      return {
        testResult: result,
        riskScore: 0,
        severity: 'low',
        businessImpact: 0,
        priority: 0,
        factors: [],
        recommendations: [],
      };
    }

    const factors = this.identifyRiskFactors(result);
    const riskScore = this.calculateRiskScore(result, factors);
    const severity = this.determineSeverity(riskScore);
    const businessImpact = this.calculateBusinessImpact(result, factors);
    const priority = this.calculatePriority(riskScore, businessImpact);
    const recommendations = this.generateRecommendations(result, factors);

    return {
      testResult: result,
      riskScore,
      severity,
      businessImpact,
      priority,
      factors,
      recommendations,
    };
  }

  /**
   * Score multiple test results
   */
  scoreTestResults(results: TestResult[]): RiskScore[] {
    return results.map(result => this.scoreTestResult(result));
  }

  /**
   * Prioritize risk scores
   */
  prioritizeRisks(scores: RiskScore[]): RiskScore[] {
    return [...scores].sort((a, b) => {
      // Sort by priority (descending)
      if (b.priority !== a.priority) {
        return b.priority - a.priority;
      }
      // Then by risk score (descending)
      if (b.riskScore !== a.riskScore) {
        return b.riskScore - a.riskScore;
      }
      // Then by severity
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      return severityOrder[b.severity] - severityOrder[a.severity];
    });
  }

  /**
   * Identify risk factors
   */
  private identifyRiskFactors(result: TestResult): RiskFactor[] {
    const factors: RiskFactor[] = [];

    // Test type factor
    const testTypeWeight = this.config.weights.testType[result.testType] || 10;
    factors.push({
      name: 'Test Type',
      impact: testTypeWeight,
      description: `${result.testType} test failure`,
    });

    // Data sensitivity factor
    const sensitivity = result.details?.resource?.sensitivity || 
                       result.details?.sensitivity || 'internal';
    const sensitivityWeight = this.config.weights.dataSensitivity[sensitivity] || 20;
    factors.push({
      name: 'Data Sensitivity',
      impact: sensitivityWeight,
      description: `Accessing ${sensitivity} data`,
    });

    // User role factor
    const userRole = result.details?.user?.role || 'unknown';
    const roleWeight = this.config.weights.userRole[userRole] || 15;
    factors.push({
      name: 'User Role',
      impact: roleWeight,
      description: `Violation by ${userRole} role`,
    });

    // Violation type factor
    const violationType = this.identifyViolationType(result);
    if (violationType) {
      const violationWeight = this.config.weights.violationType[violationType] || 20;
      factors.push({
        name: 'Violation Type',
        impact: violationWeight,
        description: `${violationType} violation`,
      });
    }

    // Error severity factor
    if (result.error) {
      factors.push({
        name: 'Error Severity',
        impact: 30,
        description: `Error: ${result.error}`,
      });
    }

    return factors;
  }

  /**
   * Calculate risk score
   */
  private calculateRiskScore(
    result: TestResult,
    factors: RiskFactor[]
  ): number {
    let score = 0;

    for (const factor of factors) {
      score += factor.impact;
    }

    // Normalize to 0-100
    return Math.min(100, score);
  }

  /**
   * Determine severity
   */
  private determineSeverity(riskScore: number): 'critical' | 'high' | 'medium' | 'low' {
    if (riskScore >= this.config.thresholds.critical) {
      return 'critical';
    } else if (riskScore >= this.config.thresholds.high) {
      return 'high';
    } else if (riskScore >= this.config.thresholds.medium) {
      return 'medium';
    } else {
      return 'low';
    }
  }

  /**
   * Calculate business impact
   */
  private calculateBusinessImpact(
    result: TestResult,
    factors: RiskFactor[]
  ): number {
    let impact = 0;

    // Data sensitivity impact
    const sensitivityFactor = factors.find(f => f.name === 'Data Sensitivity');
    if (sensitivityFactor) {
      impact += sensitivityFactor.impact * 0.4;
    }

    // Violation type impact
    const violationFactor = factors.find(f => f.name === 'Violation Type');
    if (violationFactor) {
      impact += violationFactor.impact * 0.3;
    }

    // Test type impact
    const testTypeFactor = factors.find(f => f.name === 'Test Type');
    if (testTypeFactor) {
      impact += testTypeFactor.impact * 0.3;
    }

    return Math.min(100, impact);
  }

  /**
   * Calculate priority
   */
  private calculatePriority(riskScore: number, businessImpact: number): number {
    // Priority = weighted combination of risk score and business impact
    return (riskScore * 0.6) + (businessImpact * 0.4);
  }

  /**
   * Identify violation type
   */
  private identifyViolationType(result: TestResult): string | null {
    const testName = result.testName.toLowerCase();
    const details = result.details || {};

    if (testName.includes('sql injection') || details.type === 'sql-injection') {
      return 'sql-injection';
    }
    if (testName.includes('privilege') || details.type === 'privilege-escalation') {
      return 'privilege-escalation';
    }
    if (testName.includes('pii') || testName.includes('email') || details.type === 'pii-exposure') {
      return 'pii-exposure';
    }
    if (testName.includes('over-broad') || details.type === 'over-broad-query') {
      return 'over-broad-query';
    }
    if (testName.includes('missing filter') || details.type === 'missing-filter') {
      return 'missing-filter';
    }
    if (testName.includes('join') || details.type === 'disallowed-join') {
      return 'disallowed-join';
    }
    if (details.type === 'data-leakage') {
      return 'data-leakage';
    }

    return 'policy-violation';
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    result: TestResult,
    factors: RiskFactor[]
  ): string[] {
    const recommendations: string[] = [];

    const violationType = this.identifyViolationType(result);

    switch (violationType) {
      case 'sql-injection':
        recommendations.push('Use parameterized queries to prevent SQL injection');
        recommendations.push('Implement input validation and sanitization');
        break;
      case 'privilege-escalation':
        recommendations.push('Review and restrict user permissions');
        recommendations.push('Implement principle of least privilege');
        break;
      case 'pii-exposure':
        recommendations.push('Implement PII masking or encryption');
        recommendations.push('Add field-level access controls');
        break;
      case 'over-broad-query':
        recommendations.push('Add required filters to limit data access');
        recommendations.push('Implement query result limits');
        break;
      case 'missing-filter':
        recommendations.push('Enforce required filters in query execution');
        recommendations.push('Add workspace/tenant filtering');
        break;
      case 'disallowed-join':
        recommendations.push('Block disallowed table joins');
        recommendations.push('Review join permissions for user role');
        break;
      default:
        recommendations.push('Review access control policies');
        recommendations.push('Verify policy enforcement');
    }

    // Add severity-specific recommendations
    const severity = this.determineSeverity(this.calculateRiskScore(result, factors));
    if (severity === 'critical' || severity === 'high') {
      recommendations.push('Immediate remediation required');
      recommendations.push('Consider blocking access until resolved');
    }

    return recommendations;
  }

  /**
   * Get risk summary
   */
  getRiskSummary(scores: RiskScore[]): {
    total: number;
    bySeverity: Record<string, number>;
    averageRiskScore: number;
    criticalCount: number;
  } {
    const bySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };

    let totalRiskScore = 0;

    for (const score of scores) {
      bySeverity[score.severity]++;
      totalRiskScore += score.riskScore;
    }

    return {
      total: scores.length,
      bySeverity,
      averageRiskScore: scores.length > 0 ? totalRiskScore / scores.length : 0,
      criticalCount: bySeverity.critical,
    };
  }
}

