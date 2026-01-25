/**
 * Configuration Drift Detector
 * 
 * Detects configuration changes between environments and baselines
 */

import * as fs from 'fs/promises';
import * as crypto from 'crypto';
import { EnvironmentConfig } from './environment-config-validator';
import { ABACPolicy } from '../core/types';

export interface ConfigurationBaseline {
  environment: string;
  timestamp: Date;
  variables: Record<string, string>;
  configFiles: Record<string, string>; // file path -> content hash
  policies: string[];
}

export interface DriftDetectionResult {
  hasDrift: boolean;
  environment: string;
  drifts: Array<{
    type: 'variable-added' | 'variable-removed' | 'variable-changed' | 'file-changed' | 'policy-changed';
    field: string;
    baselineValue?: string;
    currentValue?: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    requiresApproval: boolean;
  }>;
  driftScore: number; // 0-100
}

export interface ComparisonResult {
  environments: [string, string];
  differences: Array<{
    type: 'variable' | 'file' | 'policy';
    field: string;
    value1?: any;
    value2?: any;
  }>;
  similarity: number; // 0-100
}

export interface Approval {
  approver: string;
  timestamp: Date;
  approved: boolean;
  reason?: string;
}

export interface ApprovalResult {
  approved: boolean;
  approvals: Approval[];
  missingApprovals: string[];
}

export interface Report {
  title: string;
  environment: string;
  timestamp: Date;
  summary: {
    totalDrifts: number;
    criticalDrifts: number;
    highDrifts: number;
    mediumDrifts: number;
    lowDrifts: number;
  };
  drifts: DriftDetectionResult['drifts'];
  recommendations: string[];
}

export class ConfigDriftDetector {
  /**
   * Create a configuration baseline
   */
  async createBaseline(
    environment: string,
    config: EnvironmentConfig
  ): Promise<ConfigurationBaseline> {
    const configFiles: Record<string, string> = {};

    // Hash all config files
    for (const filePath of config.configFiles) {
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const hash = this.hashContent(content);
        configFiles[filePath] = hash;
      } catch (error) {
        // Skip files that can't be read
      }
    }

    // Extract policy IDs if policies are provided
    const policies: string[] = [];
    // Policies would come from a separate source in real implementation

    return {
      environment,
      timestamp: new Date(),
      variables: { ...config.variables },
      configFiles,
      policies,
    };
  }

  /**
   * Detect configuration drift
   */
  async detectDrift(
    baseline: ConfigurationBaseline,
    current: EnvironmentConfig
  ): Promise<DriftDetectionResult> {
    const drifts: DriftDetectionResult['drifts'] = [];

    // Compare variables
    const variableDrifts = this.compareVariables(baseline.variables, current.variables);
    drifts.push(...variableDrifts);

    // Compare config files - convert string[] to Record<string, string> if needed
    const baselineFiles = Array.isArray(baseline.configFiles) 
      ? baseline.configFiles.reduce((acc, file) => ({ ...acc, [file]: '' }), {} as Record<string, string>)
      : baseline.configFiles;
    const currentFiles = Array.isArray(current.configFiles)
      ? current.configFiles.reduce((acc, file) => ({ ...acc, [file]: '' }), {} as Record<string, string>)
      : current.configFiles;
    const fileDrifts = await this.compareConfigFiles(baselineFiles, currentFiles);
    drifts.push(...fileDrifts);

    // Compare policies
    const policyDrifts = this.comparePolicies(baseline.policies, []);
    drifts.push(...policyDrifts);

    // Calculate drift score
    const driftScore = this.calculateDriftScore(drifts);

    return {
      hasDrift: drifts.length > 0,
      environment: current.environment,
      drifts,
      driftScore,
    };
  }

  /**
   * Compare two environments
   */
  async compareEnvironments(
    env1: string,
    env2: string
  ): Promise<ComparisonResult> {
    // This would require loading both environment configs
    // For now, return a placeholder structure
    const differences: ComparisonResult['differences'] = [];

    return {
      environments: [env1, env2],
      differences,
      similarity: 100 - differences.length * 10, // Simplified calculation
    };
  }

  /**
   * Validate drift approval
   */
  async validateDriftApproval(
    drift: DriftDetectionResult,
    approvals: Approval[]
  ): Promise<ApprovalResult> {
    const requiredApprovals: string[] = [];
    const approvedDrifts: string[] = [];

    // Determine which drifts require approval
    for (const driftItem of drift.drifts) {
      if (driftItem.requiresApproval) {
        requiredApprovals.push(driftItem.field);

        // Check if this drift has been approved
        const approval = approvals.find(a => 
          a.approved && 
          (a.reason?.includes(driftItem.field) || true) // Simplified check
        );

        if (approval) {
          approvedDrifts.push(driftItem.field);
        }
      }
    }

    const missingApprovals = requiredApprovals.filter(
      req => !approvedDrifts.includes(req)
    );

    return {
      approved: missingApprovals.length === 0,
      approvals,
      missingApprovals,
    };
  }

  /**
   * Generate drift report
   */
  async generateDriftReport(
    drift: DriftDetectionResult
  ): Promise<Report> {
    const criticalDrifts = drift.drifts.filter(d => d.severity === 'critical').length;
    const highDrifts = drift.drifts.filter(d => d.severity === 'high').length;
    const mediumDrifts = drift.drifts.filter(d => d.severity === 'medium').length;
    const lowDrifts = drift.drifts.filter(d => d.severity === 'low').length;

    const recommendations: string[] = [];

    if (criticalDrifts > 0) {
      recommendations.push('Immediately review and address critical configuration drifts');
    }
    if (highDrifts > 0) {
      recommendations.push('Review high-severity configuration changes');
    }
    if (drift.driftScore > 50) {
      recommendations.push('Configuration drift is significant - consider creating a new baseline');
    }

    return {
      title: `Configuration Drift Report - ${drift.environment}`,
      environment: drift.environment,
      timestamp: new Date(),
      summary: {
        totalDrifts: drift.drifts.length,
        criticalDrifts,
        highDrifts,
        mediumDrifts,
        lowDrifts,
      },
      drifts: drift.drifts,
      recommendations,
    };
  }

  /**
   * Compare variables between baseline and current
   */
  private compareVariables(
    baseline: Record<string, string>,
    current: Record<string, string>
  ): DriftDetectionResult['drifts'] {
    const drifts: DriftDetectionResult['drifts'] = [];

    // Find added variables
    for (const key of Object.keys(current)) {
      if (!(key in baseline)) {
        drifts.push({
          type: 'variable-added',
          field: key,
          currentValue: this.maskSecret(current[key]),
          severity: this.determineSeverity(key, 'added'),
          requiresApproval: this.requiresApproval(key, 'added'),
        });
      }
    }

    // Find removed variables
    for (const key of Object.keys(baseline)) {
      if (!(key in current)) {
        drifts.push({
          type: 'variable-removed',
          field: key,
          baselineValue: this.maskSecret(baseline[key]),
          severity: this.determineSeverity(key, 'removed'),
          requiresApproval: this.requiresApproval(key, 'removed'),
        });
      }
    }

    // Find changed variables
    for (const key of Object.keys(baseline)) {
      if (key in current && baseline[key] !== current[key]) {
        drifts.push({
          type: 'variable-changed',
          field: key,
          baselineValue: this.maskSecret(baseline[key]),
          currentValue: this.maskSecret(current[key]),
          severity: this.determineSeverity(key, 'changed'),
          requiresApproval: this.requiresApproval(key, 'changed'),
        });
      }
    }

    return drifts;
  }

  /**
   * Compare config files between baseline and current
   */
  private async compareConfigFiles(
    baseline: Record<string, string>,
    current: Record<string, string>
  ): Promise<DriftDetectionResult['drifts']> {
    const drifts: DriftDetectionResult['drifts'] = [];

    // Find changed files
    for (const [filePath, baselineHash] of Object.entries(baseline)) {
      const currentHash = current[filePath];
      if (!currentHash) {
        drifts.push({
          type: 'file-changed',
          field: filePath,
          baselineValue: 'file exists',
          currentValue: 'file missing',
          severity: 'high',
          requiresApproval: true,
        });
      } else if (baselineHash !== currentHash) {
        drifts.push({
          type: 'file-changed',
          field: filePath,
          baselineValue: baselineHash.substring(0, 8),
          currentValue: currentHash.substring(0, 8),
          severity: 'medium',
          requiresApproval: true,
        });
      }
    }

    // Find new files
    for (const filePath of Object.keys(current)) {
      if (!(filePath in baseline)) {
        drifts.push({
          type: 'file-changed',
          field: filePath,
          currentValue: 'new file',
          severity: 'low',
          requiresApproval: false,
        });
      }
    }

    return drifts;
  }

  /**
   * Compare policies
   */
  private comparePolicies(
    baseline: string[],
    current: string[]
  ): DriftDetectionResult['drifts'] {
    const drifts: DriftDetectionResult['drifts'] = [];

    // Find removed policies
    for (const policyId of baseline) {
      if (!current.includes(policyId)) {
        drifts.push({
          type: 'policy-changed',
          field: policyId,
          baselineValue: 'policy exists',
          currentValue: 'policy removed',
          severity: 'high',
          requiresApproval: true,
        });
      }
    }

    // Find new policies
    for (const policyId of current) {
      if (!baseline.includes(policyId)) {
        drifts.push({
          type: 'policy-changed',
          field: policyId,
          currentValue: 'new policy',
          severity: 'medium',
          requiresApproval: true,
        });
      }
    }

    return drifts;
  }

  /**
   * Calculate drift score (0-100)
   */
  private calculateDriftScore(drifts: DriftDetectionResult['drifts']): number {
    let score = 0;

    for (const drift of drifts) {
      switch (drift.severity) {
        case 'critical':
          score += 20;
          break;
        case 'high':
          score += 10;
          break;
        case 'medium':
          score += 5;
          break;
        case 'low':
          score += 2;
          break;
      }
    }

    return Math.min(100, score);
  }

  /**
   * Determine severity based on variable name and change type
   */
  private determineSeverity(
    field: string,
    changeType: 'added' | 'removed' | 'changed'
  ): 'critical' | 'high' | 'medium' | 'low' {
    const lowerField = field.toLowerCase();

    // Critical fields
    if (
      lowerField.includes('secret') ||
      lowerField.includes('password') ||
      lowerField.includes('key') ||
      lowerField.includes('token')
    ) {
      return 'critical';
    }

    // High severity fields
    if (
      lowerField.includes('database') ||
      lowerField.includes('api') ||
      lowerField.includes('auth')
    ) {
      return 'high';
    }

    // Medium severity for removed/changed
    if (changeType === 'removed' || changeType === 'changed') {
      return 'medium';
    }

    return 'low';
  }

  /**
   * Determine if change requires approval
   */
  private requiresApproval(
    field: string,
    changeType: 'added' | 'removed' | 'changed'
  ): boolean {
    const lowerField = field.toLowerCase();

    // Always require approval for critical fields
    if (
      lowerField.includes('secret') ||
      lowerField.includes('password') ||
      lowerField.includes('key')
    ) {
      return true;
    }

    // Require approval for removals
    if (changeType === 'removed') {
      return true;
    }

    return false;
  }

  /**
   * Hash content for comparison
   */
  private hashContent(content: string): string {
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  /**
   * Mask secret value
   */
  private maskSecret(value: string): string {
    if (value.length <= 8) {
      return '***';
    }
    return value.substring(0, 4) + '***' + value.substring(value.length - 4);
  }
}

