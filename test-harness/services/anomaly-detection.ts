/**
 * Anomaly Detection Service
 * 
 * Detects unusual finding patterns, risk spikes, compliance drift, and attack patterns
 */

import { UnifiedFinding } from '../core/unified-finding-schema';
import { EventEmitter } from 'events';

export interface Anomaly {
  id: string;
  type: 'unusual_pattern' | 'risk_spike' | 'compliance_drift' | 'attack_pattern';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  detectedAt: Date;
  findings: UnifiedFinding[];
  metrics: Record<string, any>;
  confidence: number; // 0-1
  metadata?: Record<string, any>;
}

export interface AnomalyDetectionConfig {
  enableUnusualPatterns: boolean;
  enableRiskSpikeDetection: boolean;
  enableComplianceDriftDetection: boolean;
  enableAttackPatternDetection: boolean;
  riskSpikeThreshold?: number; // Percentage increase
  complianceDriftThreshold?: number; // Percentage decrease
  timeWindow?: number; // milliseconds
  minFindingsForPattern?: number;
}

export interface FindingPattern {
  scannerId: string;
  severity: string;
  applicationId?: string;
  component?: string;
  count: number;
  trend: 'increasing' | 'decreasing' | 'stable';
  changeRate: number; // Percentage change
}

export interface RiskSpike {
  applicationId?: string;
  baselineRisk: number;
  currentRisk: number;
  increase: number; // Percentage
  findings: UnifiedFinding[];
  timeWindow: {
    start: Date;
    end: Date;
  };
}

export interface ComplianceDrift {
  framework: string;
  controlId?: string;
  baselineCompliance: number; // Percentage
  currentCompliance: number; // Percentage
  decrease: number; // Percentage
  findings: UnifiedFinding[];
  timeWindow: {
    start: Date;
    end: Date;
  };
}

export interface AttackPattern {
  pattern: string; // e.g., 'mass-exploitation', 'lateral-movement', 'data-exfiltration'
  indicators: string[];
  findings: UnifiedFinding[];
  confidence: number;
  detectedAt: Date;
}

export class AnomalyDetectionService extends EventEmitter {
  private config: AnomalyDetectionConfig;
  private findingHistory: UnifiedFinding[] = [];
  private riskBaselines: Map<string, number> = new Map(); // applicationId -> baseline risk
  private complianceBaselines: Map<string, number> = new Map(); // framework -> baseline compliance
  private patternHistory: FindingPattern[] = [];
  private maxHistorySize: number = 10000;

  constructor(config: Partial<AnomalyDetectionConfig> = {}) {
    super();
    this.config = {
      enableUnusualPatterns: config.enableUnusualPatterns !== false,
      enableRiskSpikeDetection: config.enableRiskSpikeDetection !== false,
      enableComplianceDriftDetection: config.enableComplianceDriftDetection !== false,
      enableAttackPatternDetection: config.enableAttackPatternDetection !== false,
      riskSpikeThreshold: config.riskSpikeThreshold || 50, // 50% increase
      complianceDriftThreshold: config.complianceDriftThreshold || 10, // 10% decrease
      timeWindow: config.timeWindow || 3600000, // 1 hour
      minFindingsForPattern: config.minFindingsForPattern || 5,
    };
  }

  /**
   * Analyze findings for anomalies
   */
  async analyzeFindings(findings: UnifiedFinding[]): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    // Add to history
    this.findingHistory.push(...findings);
    if (this.findingHistory.length > this.maxHistorySize) {
      this.findingHistory = this.findingHistory.slice(-this.maxHistorySize);
    }

    // Detect unusual patterns
    if (this.config.enableUnusualPatterns) {
      const patternAnomalies = await this.detectUnusualPatterns(findings);
      anomalies.push(...patternAnomalies);
    }

    // Detect risk spikes
    if (this.config.enableRiskSpikeDetection) {
      const riskSpikes = await this.detectRiskSpikes(findings);
      anomalies.push(...riskSpikes);
    }

    // Detect compliance drift
    if (this.config.enableComplianceDriftDetection) {
      const complianceDrifts = await this.detectComplianceDrift(findings);
      anomalies.push(...complianceDrifts);
    }

    // Detect attack patterns
    if (this.config.enableAttackPatternDetection) {
      const attackPatterns = await this.detectAttackPatterns(findings);
      anomalies.push(...attackPatterns);
    }

    // Emit events for detected anomalies
    anomalies.forEach(anomaly => {
      this.emit('anomaly_detected', anomaly);
    });

    return anomalies;
  }

  /**
   * Detect unusual finding patterns
   */
  private async detectUnusualPatterns(findings: UnifiedFinding[]): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];
    const timeWindow = this.config.timeWindow || 3600000;
    const now = Date.now();
    const windowStart = new Date(now - timeWindow);

    // Group findings by pattern
    const patterns = new Map<string, FindingPattern>();

    for (const finding of findings) {
      const key = `${finding.scannerId}-${finding.severity}-${finding.asset.applicationId || 'unknown'}`;
      const pattern = patterns.get(key) || {
        scannerId: finding.scannerId,
        severity: finding.severity,
        applicationId: finding.asset.applicationId,
        component: finding.asset.component,
        count: 0,
        trend: 'stable' as const,
        changeRate: 0,
      };

      pattern.count++;
      patterns.set(key, pattern);
    }

    // Compare with historical patterns
    const historicalPatterns = this.patternHistory.filter(
      p => new Date(p.count) >= windowStart
    );

    for (const [key, pattern] of patterns) {
      const historical = historicalPatterns.find(
        p =>
          p.scannerId === pattern.scannerId &&
          p.severity === pattern.severity &&
          p.applicationId === pattern.applicationId
      );

      if (historical) {
        const changeRate = ((pattern.count - historical.count) / historical.count) * 100;
        pattern.changeRate = changeRate;
        pattern.trend = changeRate > 20 ? 'increasing' : changeRate < -20 ? 'decreasing' : 'stable';

        // Detect unusual increase
        if (changeRate > 100 && pattern.count >= (this.config.minFindingsForPattern || 5)) {
          const relatedFindings = findings.filter(
            f =>
              f.scannerId === pattern.scannerId &&
              f.severity === pattern.severity &&
              f.asset.applicationId === pattern.applicationId
          );

          anomalies.push({
            id: `anomaly-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            type: 'unusual_pattern',
            severity: this.mapChangeRateToSeverity(changeRate),
            title: `Unusual pattern detected: ${pattern.scannerId} findings increased by ${changeRate.toFixed(1)}%`,
            description: `Found ${pattern.count} ${pattern.severity} findings from ${pattern.scannerId} in the last ${timeWindow / 1000 / 60} minutes, representing a ${changeRate.toFixed(1)}% increase.`,
            detectedAt: new Date(),
            findings: relatedFindings,
            metrics: {
              pattern,
              changeRate,
              historicalCount: historical.count,
              currentCount: pattern.count,
            },
            confidence: Math.min(changeRate / 200, 1), // Cap at 1.0
          });
        }
      }
    }

    // Update pattern history
    this.patternHistory.push(...Array.from(patterns.values()));
    if (this.patternHistory.length > 1000) {
      this.patternHistory = this.patternHistory.slice(-1000);
    }

    return anomalies;
  }

  /**
   * Detect risk spikes
   */
  private async detectRiskSpikes(findings: UnifiedFinding[]): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];
    const threshold = this.config.riskSpikeThreshold || 50;

    // Group findings by application
    const appRisks = new Map<string, { findings: UnifiedFinding[]; totalRisk: number }>();

    for (const finding of findings) {
      const appId = finding.asset.applicationId || 'unknown';
      const current = appRisks.get(appId) || { findings: [], totalRisk: 0 };
      current.findings.push(finding);
      current.totalRisk += finding.riskScore || 0;
      appRisks.set(appId, current);
    }

    // Check for spikes
    for (const [appId, data] of appRisks) {
      const baseline = this.riskBaselines.get(appId) || data.totalRisk;
      const currentRisk = data.totalRisk;
      const increase = ((currentRisk - baseline) / baseline) * 100;

      if (increase >= threshold) {
        const timeWindow = this.config.timeWindow || 3600000;
        anomalies.push({
          id: `risk-spike-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: 'risk_spike',
          severity: this.mapRiskIncreaseToSeverity(increase),
          title: `Risk spike detected for application: ${appId}`,
          description: `Application risk increased by ${increase.toFixed(1)}% from baseline of ${baseline.toFixed(0)} to ${currentRisk.toFixed(0)}.`,
          detectedAt: new Date(),
          findings: data.findings,
          metrics: {
            baselineRisk: baseline,
            currentRisk,
            increase,
            applicationId: appId,
          },
          confidence: Math.min(increase / (threshold * 2), 1),
          metadata: {
            timeWindow: {
              start: new Date(Date.now() - timeWindow),
              end: new Date(),
            },
          },
        });

        // Update baseline
        this.riskBaselines.set(appId, currentRisk);
      } else {
        // Update baseline gradually
        const newBaseline = baseline * 0.9 + currentRisk * 0.1; // Exponential moving average
        this.riskBaselines.set(appId, newBaseline);
      }
    }

    return anomalies;
  }

  /**
   * Detect compliance drift
   */
  private async detectComplianceDrift(findings: UnifiedFinding[]): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];
    const threshold = this.config.complianceDriftThreshold || 10;

    // Group findings by compliance framework
    const frameworkFindings = new Map<string, UnifiedFinding[]>();

    for (const finding of findings) {
      if (finding.compliance?.frameworks) {
        for (const framework of finding.compliance.frameworks) {
          const current = frameworkFindings.get(framework) || [];
          current.push(finding);
          frameworkFindings.set(framework, current);
        }
      }
    }

    // Calculate compliance scores (simplified - in reality would check control status)
    for (const [framework, frameworkFindingsList] of frameworkFindings) {
      // Calculate current compliance (simplified)
      const totalControls = 100; // Would be actual control count
      const nonCompliantControls = frameworkFindingsList.filter(f => f.status === 'open').length;
      const currentCompliance = ((totalControls - nonCompliantControls) / totalControls) * 100;

      const baseline = this.complianceBaselines.get(framework) || currentCompliance;
      const decrease = baseline - currentCompliance;

      if (decrease >= threshold) {
        const timeWindow = this.config.timeWindow || 3600000;
        anomalies.push({
          id: `compliance-drift-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          type: 'compliance_drift',
          severity: this.mapComplianceDecreaseToSeverity(decrease),
          title: `Compliance drift detected for ${framework}`,
          description: `Compliance for ${framework} decreased by ${decrease.toFixed(1)}% from ${baseline.toFixed(1)}% to ${currentCompliance.toFixed(1)}%.`,
          detectedAt: new Date(),
          findings: frameworkFindingsList,
          metrics: {
            framework,
            baselineCompliance: baseline,
            currentCompliance,
            decrease,
            nonCompliantControls,
          },
          confidence: Math.min(decrease / (threshold * 2), 1),
          metadata: {
            timeWindow: {
              start: new Date(Date.now() - timeWindow),
              end: new Date(),
            },
          },
        });

        // Update baseline
        this.complianceBaselines.set(framework, currentCompliance);
      } else {
        // Update baseline gradually
        const newBaseline = baseline * 0.95 + currentCompliance * 0.05;
        this.complianceBaselines.set(framework, newBaseline);
      }
    }

    return anomalies;
  }

  /**
   * Detect attack patterns
   */
  private async detectAttackPatterns(findings: UnifiedFinding[]): Promise<Anomaly[]> {
    const anomalies: Anomaly[] = [];

    // Pattern: Mass exploitation (multiple critical/high findings from same scanner)
    const criticalFindings = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (criticalFindings.length >= 10) {
      const scannerCounts = new Map<string, number>();
      criticalFindings.forEach(f => {
        scannerCounts.set(f.scannerId, (scannerCounts.get(f.scannerId) || 0) + 1);
      });

      for (const [scannerId, count] of scannerCounts) {
        if (count >= 5) {
          const relatedFindings = criticalFindings.filter(f => f.scannerId === scannerId);
          anomalies.push({
            id: `attack-pattern-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
            type: 'attack_pattern',
            severity: 'critical',
            title: `Potential mass exploitation detected: ${count} critical/high findings from ${scannerId}`,
            description: `Detected ${count} critical or high severity findings from ${scannerId} in a short time window, indicating potential mass exploitation attempt.`,
            detectedAt: new Date(),
            findings: relatedFindings,
            metrics: {
              pattern: 'mass-exploitation',
              scannerId,
              count,
              indicators: ['multiple-critical-findings', 'same-scanner', 'short-time-window'],
            },
            confidence: Math.min(count / 20, 1),
            metadata: {
              pattern: 'mass-exploitation',
              indicators: ['multiple-critical-findings', 'same-scanner', 'short-time-window'],
            },
          });
        }
      }
    }

    // Pattern: Lateral movement (findings across multiple applications)
    const appFindings = new Map<string, UnifiedFinding[]>();
    findings.forEach(f => {
      const appId = f.asset.applicationId || 'unknown';
      const current = appFindings.get(appId) || [];
      current.push(f);
      appFindings.set(appId, current);
    });

    if (appFindings.size >= 5) {
      const allFindings = Array.from(appFindings.values()).flat();
      anomalies.push({
        id: `attack-pattern-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: 'attack_pattern',
        severity: 'high',
        title: `Potential lateral movement detected across ${appFindings.size} applications`,
        description: `Detected security findings across ${appFindings.size} different applications, indicating potential lateral movement.`,
        detectedAt: new Date(),
        findings: allFindings,
        metrics: {
          pattern: 'lateral-movement',
          applicationCount: appFindings.size,
          indicators: ['multiple-applications', 'similar-findings', 'short-time-window'],
        },
        confidence: Math.min(appFindings.size / 10, 1),
        metadata: {
          pattern: 'lateral-movement',
          indicators: ['multiple-applications', 'similar-findings', 'short-time-window'],
        },
      });
    }

    // Pattern: Data exfiltration (sensitive data findings)
    const sensitiveFindings = findings.filter(
      f =>
        f.title.toLowerCase().includes('pii') ||
        f.title.toLowerCase().includes('sensitive') ||
        f.title.toLowerCase().includes('credential') ||
        f.description.toLowerCase().includes('data leak')
    );

    if (sensitiveFindings.length >= 3) {
      anomalies.push({
        id: `attack-pattern-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        type: 'attack_pattern',
        severity: 'critical',
        title: `Potential data exfiltration detected: ${sensitiveFindings.length} sensitive data findings`,
        description: `Detected ${sensitiveFindings.length} findings related to sensitive data exposure, indicating potential data exfiltration attempt.`,
        detectedAt: new Date(),
        findings: sensitiveFindings,
        metrics: {
          pattern: 'data-exfiltration',
          count: sensitiveFindings.length,
          indicators: ['sensitive-data', 'multiple-findings', 'short-time-window'],
        },
        confidence: Math.min(sensitiveFindings.length / 10, 1),
        metadata: {
          pattern: 'data-exfiltration',
          indicators: ['sensitive-data', 'multiple-findings', 'short-time-window'],
        },
      });
    }

    return anomalies;
  }

  /**
   * Map change rate to severity
   */
  private mapChangeRateToSeverity(changeRate: number): 'critical' | 'high' | 'medium' | 'low' {
    if (changeRate >= 500) return 'critical';
    if (changeRate >= 200) return 'high';
    if (changeRate >= 100) return 'medium';
    return 'low';
  }

  /**
   * Map risk increase to severity
   */
  private mapRiskIncreaseToSeverity(increase: number): 'critical' | 'high' | 'medium' | 'low' {
    if (increase >= 200) return 'critical';
    if (increase >= 100) return 'high';
    if (increase >= 50) return 'medium';
    return 'low';
  }

  /**
   * Map compliance decrease to severity
   */
  private mapComplianceDecreaseToSeverity(decrease: number): 'critical' | 'high' | 'medium' | 'low' {
    if (decrease >= 30) return 'critical';
    if (decrease >= 20) return 'high';
    if (decrease >= 10) return 'medium';
    return 'low';
  }

  /**
   * Get detection statistics
   */
  getStats(): {
    historySize: number;
    riskBaselines: number;
    complianceBaselines: number;
    patternHistorySize: number;
    config: AnomalyDetectionConfig;
  } {
    return {
      historySize: this.findingHistory.length,
      riskBaselines: this.riskBaselines.size,
      complianceBaselines: this.complianceBaselines.size,
      patternHistorySize: this.patternHistory.length,
      config: this.config,
    };
  }

  /**
   * Reset baselines
   */
  resetBaselines(): void {
    this.riskBaselines.clear();
    this.complianceBaselines.clear();
    this.patternHistory = [];
  }
}

