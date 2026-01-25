import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateServiceNowBaselineDto } from './dto/create-servicenow-baseline.dto';
import { UpdateServiceNowBaselineDto } from './dto/update-servicenow-baseline.dto';
import { ServiceNowDataProtectionBaseline } from '../baselines/interfaces/servicenow-baseline.interface';
import { BaselineComparison, BaselineDifference, DriftDetectionResult } from '../baselines/interfaces/base-baseline.interface';

@Injectable()
export class ServiceNowBaselinesService {
  private readonly logger = new Logger(ServiceNowBaselinesService.name);
  private readonly dataFile = path.join(process.cwd(), 'data', 'servicenow-baselines.json');
  private baselines: ServiceNowDataProtectionBaseline[] = [];

  constructor() {
    this.loadData().catch(err => {
      this.logger.error('Error loading ServiceNow baselines data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      try {
        const data = await fs.readFile(this.dataFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.baselines = [];
          await this.saveData();
          return;
        }
        const parsed = JSON.parse(data);
        this.baselines = (Array.isArray(parsed) ? parsed : []).map((b: any) => ({
          ...b,
          platform: 'servicenow' as const,
          createdAt: b.createdAt ? new Date(b.createdAt) : new Date(),
          updatedAt: b.updatedAt ? new Date(b.updatedAt) : new Date(),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.baselines = [];
          await this.saveData();
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error, initializing empty:', readError.message);
          this.baselines = [];
          await this.saveData();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading ServiceNow baselines data:', error);
      this.baselines = [];
    }
  }

  private async saveData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      await fs.writeFile(this.dataFile, JSON.stringify(this.baselines, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving ServiceNow baselines data:', error);
      throw error;
    }
  }

  async getBaselines(): Promise<ServiceNowDataProtectionBaseline[]> {
    await this.loadData();
    return [...this.baselines];
  }

  async getBaseline(id: string): Promise<ServiceNowDataProtectionBaseline> {
    await this.loadData();
    const baseline = this.baselines.find(b => b.id === id);
    if (!baseline) {
      throw new NotFoundException(`ServiceNow baseline with ID ${id} not found`);
    }
    return baseline;
  }

  async createBaseline(dto: CreateServiceNowBaselineDto): Promise<ServiceNowDataProtectionBaseline> {
    await this.loadData();
    const baseline: ServiceNowDataProtectionBaseline = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description || '',
      environment: dto.environment,
      version: dto.version || '1.0.0',
      platform: 'servicenow',
      config: dto.config || {},
      createdBy: dto.createdBy,
      tags: dto.tags || [],
      isActive: dto.isActive !== undefined ? dto.isActive : true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.baselines.push(baseline);
    await this.saveData();
    return baseline;
  }

  async updateBaseline(id: string, dto: UpdateServiceNowBaselineDto): Promise<ServiceNowDataProtectionBaseline> {
    await this.loadData();
    const index = this.baselines.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`ServiceNow baseline with ID ${id} not found`);
    }
    const existing = this.baselines[index];
    this.baselines[index] = {
      ...existing,
      name: dto.name !== undefined ? dto.name : existing.name,
      description: dto.description !== undefined ? dto.description : existing.description,
      environment: dto.environment !== undefined ? dto.environment : existing.environment,
      version: dto.version !== undefined ? dto.version : existing.version,
      config: dto.config !== undefined ? dto.config : existing.config,
      tags: dto.tags !== undefined ? dto.tags : existing.tags,
      isActive: dto.isActive !== undefined ? dto.isActive : existing.isActive,
      createdBy: dto.createdBy !== undefined ? dto.createdBy : existing.createdBy,
      updatedAt: new Date(),
    };
    await this.saveData();
    return this.baselines[index];
  }

  async deleteBaseline(id: string): Promise<void> {
    await this.loadData();
    const index = this.baselines.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`ServiceNow baseline with ID ${id} not found`);
    }
    this.baselines.splice(index, 1);
    await this.saveData();
  }

  async compareBaseline(id: string, currentConfig: Record<string, any>): Promise<BaselineComparison> {
    const baseline = await this.getBaseline(id);
    const differences: BaselineDifference[] = [];
    
    const baselineConfig = baseline.config || {};
    const baselineKeys = this.getAllKeys(baselineConfig);
    const currentKeys = this.getAllKeys(currentConfig);

    // Find added/modified/removed keys
    currentKeys.forEach(key => {
      if (!baselineKeys.includes(key)) {
        differences.push({
          type: 'added',
          path: key,
          key: key.split('.').pop() || key,
          currentValue: this.getNestedValue(currentConfig, key),
          severity: this.calculateSeverity('added', key, currentConfig),
          description: `New configuration added: ${key}`,
        });
      } else {
        const baselineValue = this.getNestedValue(baselineConfig, key);
        const currentValue = this.getNestedValue(currentConfig, key);
        if (JSON.stringify(baselineValue) !== JSON.stringify(currentValue)) {
          differences.push({
            type: 'modified',
            path: key,
            key: key.split('.').pop() || key,
            baselineValue,
            currentValue,
            severity: this.calculateSeverity('modified', key, currentConfig, baselineConfig),
            description: `Configuration modified: ${key}`,
            hipaaImpact: this.getHIPAImpact(key, baselineValue, currentValue),
          });
        }
      }
    });

    baselineKeys.forEach(key => {
      if (!currentKeys.includes(key)) {
        differences.push({
          type: 'removed',
          path: key,
          key: key.split('.').pop() || key,
          baselineValue: this.getNestedValue(baselineConfig, key),
          severity: this.calculateSeverity('removed', key, baselineConfig),
          description: `Configuration removed: ${key}`,
          hipaaImpact: this.getHIPAImpact(key, this.getNestedValue(baselineConfig, key), undefined),
        });
      }
    });

    // Check for encryption gaps
    const encryptionGaps = this.detectEncryptionGaps(baselineConfig, currentConfig);
    differences.push(...encryptionGaps);

    // Check for access control issues
    const accessControlIssues = this.detectAccessControlIssues(baselineConfig, currentConfig);
    differences.push(...accessControlIssues);

    // Check for retention policy violations
    const retentionViolations = this.detectRetentionViolations(baselineConfig, currentConfig);
    differences.push(...retentionViolations);

    const riskScore = this.calculateRiskScore(differences);
    const complianceScore = this.calculateHIPAAComplianceScore(baselineConfig, currentConfig, differences);

    return {
      baselineId: id,
      baselineName: baseline.name,
      differences,
      hasChanges: differences.length > 0,
      riskScore,
      complianceScore,
    };
  }

  async detectDrift(id: string, currentConfig: Record<string, any>): Promise<DriftDetectionResult> {
    const comparison = await this.compareBaseline(id, currentConfig);
    const baseline = await this.getBaseline(id);

    const hipaaCompliance = this.calculateHIPAACompliance(baseline.config, currentConfig, comparison.differences);
    const recommendations = this.generateRecommendations(comparison.differences, baseline.config, currentConfig);

    return {
      baselineId: id,
      baselineName: baseline.name,
      hasDrift: comparison.hasChanges,
      driftScore: comparison.riskScore || 0,
      complianceScore: comparison.complianceScore || 0,
      drifts: comparison.differences,
      hipaaCompliance,
      recommendations,
    };
  }

  // Helper methods
  private getAllKeys(obj: any, prefix = ''): string[] {
    const keys: string[] = [];
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      for (const key in obj) {
        const fullKey = prefix ? `${prefix}.${key}` : key;
        keys.push(fullKey);
        if (obj[key] && typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
          keys.push(...this.getAllKeys(obj[key], fullKey));
        }
      }
    }
    return keys;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  private calculateSeverity(
    type: 'added' | 'removed' | 'modified',
    path: string,
    config: Record<string, any>,
    baselineConfig?: Record<string, any>
  ): 'critical' | 'high' | 'medium' | 'low' {
    if (path.includes('encryption') || path.includes('Encryption')) return 'critical';
    if (path.includes('access') || path.includes('acl') || path.includes('role')) return 'high';
    if (path.includes('PHI') || path.includes('phi') || path.includes('dataClassification')) return 'critical';
    if (path.includes('audit') || path.includes('logging')) return 'high';
    if (path.includes('retention') || path.includes('archive')) return 'high';
    if (path.includes('api') || path.includes('integration')) return 'medium';
    return type === 'removed' ? 'high' : 'medium';
  }

  private getHIPAImpact(
    path: string,
    baselineValue: any,
    currentValue: any
  ): { rule?: string; requirement?: string } | undefined {
    if (path.includes('encryption')) {
      return {
        rule: 'HIPAA Security Rule §164.312(a)(2)(iv) & §164.312(e)(2)(ii)',
        requirement: 'Encryption of PHI at rest and in transit',
      };
    }
    if (path.includes('access') || path.includes('acl') || path.includes('role')) {
      return {
        rule: 'HIPAA Privacy Rule §164.502(b)',
        requirement: 'Minimum necessary access to PHI',
      };
    }
    if (path.includes('audit') || path.includes('logging')) {
      return {
        rule: 'HIPAA Security Rule §164.312(b)',
        requirement: 'Audit controls to record and examine activity',
      };
    }
    if (path.includes('retention')) {
      return {
        rule: 'HIPAA Retention Requirements',
        requirement: 'PHI must be retained for minimum 6 years',
      };
    }
    return undefined;
  }

  private detectEncryptionGaps(
    baseline: Record<string, any>,
    current: Record<string, any>
  ): BaselineDifference[] {
    const gaps: BaselineDifference[] = [];
    
    const baselineEncryption = baseline.encryption;
    const currentEncryption = current.encryption;

    if (baselineEncryption?.fieldEncryption?.enabled && !currentEncryption?.fieldEncryption?.enabled) {
      gaps.push({
        type: 'encryption_gap',
        path: 'encryption.fieldEncryption.enabled',
        key: 'fieldEncryption',
        baselineValue: true,
        currentValue: false,
        severity: 'critical',
        description: 'Field encryption is disabled but required by baseline',
        hipaaImpact: {
          rule: 'HIPAA Security Rule §164.312(a)(2)(iv)',
          requirement: 'Encryption of PHI at rest',
        },
      });
    }

    if (baselineEncryption?.databaseEncryption?.enabled && !currentEncryption?.databaseEncryption?.enabled) {
      gaps.push({
        type: 'encryption_gap',
        path: 'encryption.databaseEncryption.enabled',
        key: 'databaseEncryption',
        baselineValue: true,
        currentValue: false,
        severity: 'critical',
        description: 'Database encryption (TDE) is disabled but required by baseline',
        hipaaImpact: {
          rule: 'HIPAA Security Rule §164.312(a)(2)(iv)',
          requirement: 'Encryption of PHI at rest',
        },
      });
    }

    if (baselineEncryption?.sslTls?.enabled && !currentEncryption?.sslTls?.enabled) {
      gaps.push({
        type: 'encryption_gap',
        path: 'encryption.sslTls.enabled',
        key: 'sslTls',
        baselineValue: true,
        currentValue: false,
        severity: 'critical',
        description: 'SSL/TLS encryption is disabled but required by baseline',
        hipaaImpact: {
          rule: 'HIPAA Security Rule §164.312(e)(2)(ii)',
          requirement: 'Encryption of PHI in transit',
        },
      });
    }

    return gaps;
  }

  private detectAccessControlIssues(
    baseline: Record<string, any>,
    current: Record<string, any>
  ): BaselineDifference[] {
    const issues: BaselineDifference[] = [];

    // Check if ACLs are less restrictive than baseline
    const baselineACLs = baseline.accessControls?.acls || [];
    const currentACLs = current.accessControls?.acls || [];

    // Check for missing ACLs
    baselineACLs.forEach((baselineACL: any) => {
      const currentACL = currentACLs.find((a: any) => a.name === baselineACL.name);
      if (!currentACL && baselineACL.active) {
        issues.push({
          type: 'access_control_issue',
          path: `accessControls.acls.${baselineACL.name}`,
          key: baselineACL.name,
          baselineValue: baselineACL,
          currentValue: undefined,
          severity: 'high',
          description: `ACL ${baselineACL.name} is missing but required by baseline`,
          hipaaImpact: {
            rule: 'HIPAA Privacy Rule §164.502(b)',
            requirement: 'Minimum necessary access to PHI',
          },
        });
      }
    });

    return issues;
  }

  private detectRetentionViolations(
    baseline: Record<string, any>,
    current: Record<string, any>
  ): BaselineDifference[] {
    const violations: BaselineDifference[] = [];

    const baselinePolicies = baseline.dataRetention?.policies || [];
    const currentPolicies = current.dataRetention?.policies || [];

    baselinePolicies.forEach((baselinePolicy: any) => {
      if (baselinePolicy.hipaaCompliant) {
        const currentPolicy = currentPolicies.find((p: any) => p.table === baselinePolicy.table);
        if (currentPolicy && currentPolicy.retentionPeriod < 2190) { // 6 years = 2190 days
          violations.push({
            type: 'retention_policy_violation',
            path: `dataRetention.policies.${baselinePolicy.table}.retentionPeriod`,
            key: baselinePolicy.table,
            baselineValue: baselinePolicy.retentionPeriod,
            currentValue: currentPolicy.retentionPeriod,
            severity: 'high',
            description: `Retention period for ${baselinePolicy.table} is below HIPAA requirement (6 years minimum)`,
            hipaaImpact: {
              rule: 'HIPAA Retention Requirements',
              requirement: 'PHI must be retained for minimum 6 years',
            },
          });
        }
      }
    });

    return violations;
  }

  private calculateRiskScore(differences: BaselineDifference[]): number {
    if (differences.length === 0) return 0;
    const weights = { critical: 40, high: 25, medium: 15, low: 5 };
    let totalScore = 0;
    differences.forEach(diff => {
      totalScore += weights[diff.severity] || 0;
    });
    return Math.min(100, totalScore);
  }

  private calculateHIPAAComplianceScore(
    baseline: Record<string, any>,
    current: Record<string, any>,
    differences: BaselineDifference[]
  ): number {
    let score = 100;
    const penalties = { critical: 20, high: 10, medium: 5, low: 2 };

    differences.forEach(diff => {
      if (diff.hipaaImpact) {
        score -= penalties[diff.severity] || 0;
      }
    });

    if (baseline.encryption?.fieldEncryption?.enabled && !current.encryption?.fieldEncryption?.enabled) score -= 15;
    if (baseline.encryption?.databaseEncryption?.enabled && !current.encryption?.databaseEncryption?.enabled) score -= 15;
    if (baseline.auditLogging?.tableAuditEnabled && !current.auditLogging?.tableAuditEnabled) score -= 10;

    return Math.max(0, score);
  }

  private calculateHIPAACompliance(
    baseline: Record<string, any>,
    current: Record<string, any>,
    differences: BaselineDifference[]
  ): DriftDetectionResult['hipaaCompliance'] {
    const violations: Array<{
      rule: string;
      requirement: string;
      severity: string;
      description: string;
    }> = [];

    differences.forEach(diff => {
      if (diff.hipaaImpact) {
        violations.push({
          rule: diff.hipaaImpact.rule || '',
          requirement: diff.hipaaImpact.requirement || '',
          severity: diff.severity,
          description: diff.description,
        });
      }
    });

    const securityRuleScore = this.calculateSecurityRuleScore(baseline, current, differences);
    const privacyRuleScore = this.calculatePrivacyRuleScore(baseline, current, differences);
    const breachNotificationScore = this.calculateBreachNotificationScore(baseline, current, differences);
    const overallScore = Math.round((securityRuleScore + privacyRuleScore + breachNotificationScore) / 3);

    return {
      securityRuleScore,
      privacyRuleScore,
      breachNotificationScore,
      overallScore,
      violations,
    };
  }

  private calculateSecurityRuleScore(
    baseline: Record<string, any>,
    current: Record<string, any>,
    differences: BaselineDifference[]
  ): number {
    let score = 100;
    if (baseline.encryption && !current.encryption) score -= 30;
    if (baseline.encryption?.fieldEncryption?.enabled && !current.encryption?.fieldEncryption?.enabled) score -= 20;
    if (baseline.encryption?.databaseEncryption?.enabled && !current.encryption?.databaseEncryption?.enabled) score -= 20;
    const accessControlDiffs = differences.filter(d => d.type === 'access_control_issue');
    score -= accessControlDiffs.length * 10;
    if (baseline.auditLogging?.tableAuditEnabled && !current.auditLogging?.tableAuditEnabled) score -= 15;
    return Math.max(0, score);
  }

  private calculatePrivacyRuleScore(
    baseline: Record<string, any>,
    current: Record<string, any>,
    differences: BaselineDifference[]
  ): number {
    let score = 100;
    const accessControlDiffs = differences.filter(d => d.type === 'access_control_issue');
    score -= accessControlDiffs.length * 10;
    return Math.max(0, score);
  }

  private calculateBreachNotificationScore(
    baseline: Record<string, any>,
    current: Record<string, any>,
    differences: BaselineDifference[]
  ): number {
    let score = 100;
    if (baseline.auditLogging?.tableAuditEnabled && !current.auditLogging?.tableAuditEnabled) score -= 30;
    const encryptionGaps = differences.filter(d => d.type === 'encryption_gap');
    score -= encryptionGaps.length * 15;
    return Math.max(0, score);
  }

  private generateRecommendations(
    differences: BaselineDifference[],
    baseline: Record<string, any>,
    current: Record<string, any>
  ): Array<{ priority: 'critical' | 'high' | 'medium' | 'low'; action: string; description: string }> {
    const recommendations: Array<{ priority: 'critical' | 'high' | 'medium' | 'low'; action: string; description: string }> = [];

    differences.forEach(diff => {
      if (diff.type === 'encryption_gap') {
        recommendations.push({
          priority: 'critical',
          action: 'Enable encryption',
          description: `Enable ${diff.key} encryption to meet HIPAA Security Rule requirements`,
        });
      } else if (diff.type === 'access_control_issue') {
        recommendations.push({
          priority: 'high',
          action: 'Review access controls',
          description: diff.description,
        });
      } else if (diff.type === 'retention_policy_violation') {
        recommendations.push({
          priority: 'high',
          action: 'Update retention policy',
          description: 'Ensure retention period meets HIPAA 6-year minimum requirement',
        });
      } else if (diff.severity === 'critical') {
        recommendations.push({
          priority: 'critical',
          action: 'Review configuration',
          description: diff.description,
        });
      }
    });

    return recommendations;
  }
}
