import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateIDPBaselineDto } from './dto/create-idp-baseline.dto';
import { UpdateIDPBaselineDto } from './dto/update-idp-baseline.dto';
import { IDPKubernetesDataProtectionBaseline } from '../baselines/interfaces/idp-kubernetes-baseline.interface';
import { BaselineComparison, BaselineDifference, DriftDetectionResult } from '../baselines/interfaces/base-baseline.interface';

@Injectable()
export class IDPKubernetesBaselinesService {
  private readonly logger = new Logger(IDPKubernetesBaselinesService.name);
  private readonly dataFile = path.join(process.cwd(), 'data', 'idp-kubernetes-baselines.json');
  private baselines: IDPKubernetesDataProtectionBaseline[] = [];

  constructor() {
    this.loadData().catch(err => {
      this.logger.error('Error loading IDP/Kubernetes baselines data on startup:', err);
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
          platform: 'idp-kubernetes' as const,
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
      this.logger.error('Error loading IDP/Kubernetes baselines data:', error);
      this.baselines = [];
    }
  }

  private async saveData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      await fs.writeFile(this.dataFile, JSON.stringify(this.baselines, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving IDP/Kubernetes baselines data:', error);
      throw error;
    }
  }

  async getBaselines(): Promise<IDPKubernetesDataProtectionBaseline[]> {
    await this.loadData();
    return [...this.baselines];
  }

  async getBaseline(id: string): Promise<IDPKubernetesDataProtectionBaseline> {
    await this.loadData();
    const baseline = this.baselines.find(b => b.id === id);
    if (!baseline) {
      throw new NotFoundException(`IDP/Kubernetes baseline with ID ${id} not found`);
    }
    return baseline;
  }

  async createBaseline(dto: CreateIDPBaselineDto): Promise<IDPKubernetesDataProtectionBaseline> {
    await this.loadData();
    const baseline: IDPKubernetesDataProtectionBaseline = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description || '',
      environment: dto.environment,
      version: dto.version || '1.0.0',
      platform: 'idp-kubernetes',
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

  async updateBaseline(id: string, dto: UpdateIDPBaselineDto): Promise<IDPKubernetesDataProtectionBaseline> {
    await this.loadData();
    const index = this.baselines.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`IDP/Kubernetes baseline with ID ${id} not found`);
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
      throw new NotFoundException(`IDP/Kubernetes baseline with ID ${id} not found`);
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
    if (path.includes('secret') || path.includes('encryption')) return 'critical';
    if (path.includes('rbac') || path.includes('role') || path.includes('networkPolicy')) return 'high';
    if (path.includes('PHI') || path.includes('phi') || path.includes('dataClassification')) return 'critical';
    if (path.includes('audit') || path.includes('logging')) return 'high';
    if (path.includes('podSecurity') || path.includes('securityContext')) return 'high';
    return type === 'removed' ? 'high' : 'medium';
  }

  private getHIPAImpact(
    path: string,
    baselineValue: any,
    currentValue: any
  ): { rule?: string; requirement?: string } | undefined {
    if (path.includes('secret') || path.includes('encryption')) {
      return {
        rule: 'HIPAA Security Rule §164.312(a)(2)(iv)',
        requirement: 'Encryption of PHI at rest and secure secrets management',
      };
    }
    if (path.includes('rbac') || path.includes('role') || path.includes('networkPolicy')) {
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
    return undefined;
  }

  private detectEncryptionGaps(
    baseline: Record<string, any>,
    current: Record<string, any>
  ): BaselineDifference[] {
    const gaps: BaselineDifference[] = [];
    
    const baselineEncryption = baseline.encryptionAtRest;
    const currentEncryption = current.encryptionAtRest;

    if (baselineEncryption?.enabled && !currentEncryption?.enabled) {
      gaps.push({
        type: 'encryption_gap',
        path: 'encryptionAtRest.enabled',
        key: 'encryptionAtRest',
        baselineValue: true,
        currentValue: false,
        severity: 'critical',
        description: 'Encryption at rest is disabled but required by baseline',
        hipaaImpact: {
          rule: 'HIPAA Security Rule §164.312(a)(2)(iv)',
          requirement: 'Encryption of PHI at rest',
        },
      });
    }

    // Check secrets encryption
    const baselineSecrets = baseline.secretsManagement?.secretStores || [];
    const currentSecrets = current.secretsManagement?.secretStores || [];
    
    baselineSecrets.forEach((baselineStore: any) => {
      const currentStore = currentSecrets.find((s: any) => s.name === baselineStore.name);
      if (currentStore && baselineStore.encryption?.enabled && !currentStore.encryption?.enabled) {
        gaps.push({
          type: 'encryption_gap',
          path: `secretsManagement.secretStores.${baselineStore.name}.encryption.enabled`,
          key: baselineStore.name,
          baselineValue: true,
          currentValue: false,
          severity: 'critical',
          description: `Secret store ${baselineStore.name} encryption is disabled`,
          hipaaImpact: {
            rule: 'HIPAA Security Rule §164.312(a)(2)(iv)',
            requirement: 'Encryption of PHI credentials and secrets',
          },
        });
      }
    });

    return gaps;
  }

  private detectAccessControlIssues(
    baseline: Record<string, any>,
    current: Record<string, any>
  ): BaselineDifference[] {
    const issues: BaselineDifference[] = [];

    // Check RBAC roles for excessive privileges
    const baselineRoles = baseline.rbacDataAccess?.roles || [];
    const currentRoles = current.rbacDataAccess?.roles || [];

    baselineRoles.forEach((baselineRole: any) => {
      const currentRole = currentRoles.find((r: any) => r.name === baselineRole.name);
      if (currentRole) {
        // Check for excessive resource access
        const baselineRules = baselineRole.rules || [];
        const currentRules = currentRole.rules || [];
        
        // Check if current role has access to resources not in baseline
        const baselineResources = new Set(
          baselineRules.flatMap((r: any) => r.resources || [])
        );
        const currentResources = new Set(
          currentRules.flatMap((r: any) => r.resources || [])
        );
        
        const excessiveResources = Array.from(currentResources).filter(
          (r: any) => !baselineResources.has(r)
        );
        
        if (excessiveResources.length > 0) {
          issues.push({
            type: 'access_control_issue',
            path: `rbacDataAccess.roles.${baselineRole.name}.rules`,
            key: baselineRole.name,
            baselineValue: baselineRules,
            currentValue: currentRules,
            severity: 'high',
            description: `Role ${baselineRole.name} has access to resources not in baseline: ${excessiveResources.join(', ')}`,
            hipaaImpact: {
              rule: 'HIPAA Privacy Rule §164.502(b)',
              requirement: 'Minimum necessary access to PHI',
            },
          });
        }
      }
    });

    // Check network policies
    const baselineNetworkPolicies = baseline.networkPolicies || [];
    const currentNetworkPolicies = current.networkPolicies || [];
    
    if (baselineNetworkPolicies.length > 0 && currentNetworkPolicies.length === 0) {
      issues.push({
        type: 'access_control_issue',
        path: 'networkPolicies',
        key: 'networkPolicies',
        baselineValue: baselineNetworkPolicies.length,
        currentValue: 0,
        severity: 'high',
        description: 'No network policies configured, baseline requires network isolation',
        hipaaImpact: {
          rule: 'HIPAA Privacy Rule §164.502(b)',
          requirement: 'Network isolation to prevent unauthorized PHI access',
        },
      });
    }

    return issues;
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

    if (baseline.encryptionAtRest?.enabled && !current.encryptionAtRest?.enabled) score -= 15;
    if (baseline.auditLogging?.enabled && !current.auditLogging?.enabled) score -= 10;
    if ((baseline.networkPolicies?.length || 0) > 0 && (current.networkPolicies?.length || 0) === 0) score -= 10;

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
    if (baseline.encryptionAtRest?.enabled && !current.encryptionAtRest?.enabled) score -= 30;
    const encryptionGaps = differences.filter(d => d.type === 'encryption_gap');
    score -= encryptionGaps.length * 15;
    if (baseline.auditLogging?.enabled && !current.auditLogging?.enabled) score -= 15;
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
    if ((baseline.networkPolicies?.length || 0) > 0 && (current.networkPolicies?.length || 0) === 0) score -= 20;
    return Math.max(0, score);
  }

  private calculateBreachNotificationScore(
    baseline: Record<string, any>,
    current: Record<string, any>,
    differences: BaselineDifference[]
  ): number {
    let score = 100;
    if (baseline.auditLogging?.enabled && !current.auditLogging?.enabled) score -= 30;
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
