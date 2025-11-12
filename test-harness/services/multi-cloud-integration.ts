/**
 * Multi-Cloud Integration Service
 * 
 * Provides unified interface for managing security findings across multiple cloud providers
 */

import { UnifiedFinding } from '../core/unified-finding-schema';
import { AWSSecurityHubAdapter } from './scanner-adapters/aws-security-hub-adapter';
import { AzureSecurityCenterAdapter } from './scanner-adapters/azure-security-center-adapter';
import { GCPSecurityCommandCenterAdapter } from './scanner-adapters/gcp-security-command-center-adapter';
import { BaseScannerAdapter } from './scanner-adapters/base-adapter';

export interface CloudProviderConfig {
  provider: 'aws' | 'azure' | 'gcp';
  enabled: boolean;
  config: Record<string, any>;
  regions?: string[];
  resourceTypes?: string[];
}

export interface MultiCloudFinding {
  finding: UnifiedFinding;
  provider: 'aws' | 'azure' | 'gcp';
  region: string;
  resourceId: string;
  accountId?: string;
  subscriptionId?: string;
  projectId?: string;
}

export interface CloudProviderSummary {
  provider: 'aws' | 'azure' | 'gcp';
  totalFindings: number;
  findingsBySeverity: Record<string, number>;
  findingsByRegion: Record<string, number>;
  riskScore: number;
  lastScanTime?: Date;
}

export class MultiCloudIntegration {
  private adapters: Map<string, BaseScannerAdapter> = new Map();
  private configs: Map<string, CloudProviderConfig> = new Map();

  /**
   * Register a cloud provider
   */
  registerProvider(config: CloudProviderConfig): void {
    this.configs.set(config.provider, config);

    if (config.enabled) {
      let adapter: BaseScannerAdapter;

      switch (config.provider) {
        case 'aws':
          adapter = new AWSSecurityHubAdapter(config.config);
          break;
        case 'azure':
          adapter = new AzureSecurityCenterAdapter(config.config);
          break;
        case 'gcp':
          adapter = new GCPSecurityCommandCenterAdapter(config.config);
          break;
        default:
          throw new Error(`Unsupported cloud provider: ${config.provider}`);
      }

      this.adapters.set(config.provider, adapter);
    }
  }

  /**
   * Normalize findings from a specific cloud provider
   */
  async normalizeProviderFindings(
    provider: 'aws' | 'azure' | 'gcp',
    rawFindings: any[]
  ): Promise<UnifiedFinding[]> {
    const adapter = this.adapters.get(provider);
    if (!adapter) {
      throw new Error(`Provider ${provider} not registered or not enabled`);
    }

    const normalized: UnifiedFinding[] = [];

    for (const rawFinding of rawFindings) {
      try {
        if (adapter.validate(rawFinding)) {
          const normalizedFinding = adapter.normalize(rawFinding);
          normalized.push(normalizedFinding);
        }
      } catch (error: any) {
        console.error(`Failed to normalize finding from ${provider}:`, error.message);
      }
    }

    return normalized;
  }

  /**
   * Aggregate findings across all cloud providers
   */
  async aggregateFindings(
    providerFindings: Map<'aws' | 'azure' | 'gcp', any[]>
  ): Promise<MultiCloudFinding[]> {
    const aggregated: MultiCloudFinding[] = [];

    for (const [provider, rawFindings] of providerFindings.entries()) {
      const normalized = await this.normalizeProviderFindings(provider, rawFindings);

      for (const finding of normalized) {
        const multiCloudFinding: MultiCloudFinding = {
          finding,
          provider,
          region: this.extractRegion(finding, provider),
          resourceId: finding.asset?.component || finding.id,
          accountId: provider === 'aws' ? this.extractAccountId(finding) : undefined,
          subscriptionId: provider === 'azure' ? this.extractSubscriptionId(finding) : undefined,
          projectId: provider === 'gcp' ? this.extractProjectId(finding) : undefined,
        };

        aggregated.push(multiCloudFinding);
      }
    }

    return aggregated;
  }

  /**
   * Get summary statistics for each cloud provider
   */
  async getProviderSummaries(
    findings: MultiCloudFinding[]
  ): Promise<Map<string, CloudProviderSummary>> {
    const summaries = new Map<string, CloudProviderSummary>();

    const providers: ('aws' | 'azure' | 'gcp')[] = ['aws', 'azure', 'gcp'];

    for (const provider of providers) {
      const providerFindings = findings.filter(f => f.provider === provider);

      const findingsBySeverity: Record<string, number> = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      const findingsByRegion: Record<string, number> = {};

      let totalRiskScore = 0;

      for (const multiCloudFinding of providerFindings) {
        const severity = multiCloudFinding.finding.severity;
        findingsBySeverity[severity] = (findingsBySeverity[severity] || 0) + 1;

        const region = multiCloudFinding.region || 'unknown';
        findingsByRegion[region] = (findingsByRegion[region] || 0) + 1;

        totalRiskScore += multiCloudFinding.finding.riskScore || 0;
      }

      const avgRiskScore = providerFindings.length > 0 
        ? totalRiskScore / providerFindings.length 
        : 0;

      summaries.set(provider, {
        provider,
        totalFindings: providerFindings.length,
        findingsBySeverity,
        findingsByRegion,
        riskScore: Math.round(avgRiskScore),
        lastScanTime: providerFindings.length > 0 
          ? new Date(Math.max(...providerFindings.map(f => 
              new Date(f.finding.createdAt).getTime()))) 
          : undefined,
      });
    }

    return summaries;
  }

  /**
   * Find duplicate findings across cloud providers
   */
  findCrossCloudDuplicates(findings: MultiCloudFinding[]): Map<string, MultiCloudFinding[]> {
    const duplicates = new Map<string, MultiCloudFinding[]>();

    // Group by similar characteristics
    const groups = new Map<string, MultiCloudFinding[]>();

    for (const finding of findings) {
      const key = this.generateDuplicateKey(finding);
      if (!groups.has(key)) {
        groups.set(key, []);
      }
      groups.get(key)!.push(finding);
    }

    // Find groups with multiple providers
    for (const [key, group] of groups.entries()) {
      if (group.length > 1) {
        const providers = new Set(group.map(f => f.provider));
        if (providers.size > 1) {
          duplicates.set(key, group);
        }
      }
    }

    return duplicates;
  }

  /**
   * Get findings by cloud provider
   */
  getFindingsByProvider(findings: MultiCloudFinding[]): Map<string, MultiCloudFinding[]> {
    const byProvider = new Map<string, MultiCloudFinding[]>();

    for (const finding of findings) {
      if (!byProvider.has(finding.provider)) {
        byProvider.set(finding.provider, []);
      }
      byProvider.get(finding.provider)!.push(finding);
    }

    return byProvider;
  }

  /**
   * Get findings by region across all providers
   */
  getFindingsByRegion(findings: MultiCloudFinding[]): Map<string, MultiCloudFinding[]> {
    const byRegion = new Map<string, MultiCloudFinding[]>();

    for (const finding of findings) {
      const region = finding.region || 'unknown';
      if (!byRegion.has(region)) {
        byRegion.set(region, []);
      }
      byRegion.get(region)!.push(finding);
    }

    return byRegion;
  }

  private extractRegion(finding: UnifiedFinding, provider: string): string {
    const location = finding.asset?.location;
    if (location?.region) {
      return location.region;
    }

    // Try to extract from resource ID
    const resourceId = finding.asset?.component || '';
    if (provider === 'aws') {
      const match = resourceId.match(/arn:aws:[^:]+:([^:]+):/);
      if (match) return match[1];
    } else if (provider === 'azure') {
      const match = resourceId.match(/\/locations\/([^\/]+)/);
      if (match) return match[1];
    } else if (provider === 'gcp') {
      const match = resourceId.match(/\/locations\/([^\/]+)/);
      if (match) return match[1];
    }

    return 'unknown';
  }

  private extractAccountId(finding: UnifiedFinding): string | undefined {
    const resourceId = finding.asset?.component || '';
    const match = resourceId.match(/arn:aws:[^:]+:[^:]+:(\d+):/);
    return match ? match[1] : undefined;
  }

  private extractSubscriptionId(finding: UnifiedFinding): string | undefined {
    const resourceId = finding.asset?.component || '';
    const match = resourceId.match(/\/subscriptions\/([^\/]+)/);
    return match ? match[1] : undefined;
  }

  private extractProjectId(finding: UnifiedFinding): string | undefined {
    const resourceId = finding.asset?.component || '';
    const match = resourceId.match(/\/projects\/([^\/]+)/);
    return match ? match[1] : undefined;
  }

  private generateDuplicateKey(finding: MultiCloudFinding): string {
    // Generate key based on finding characteristics
    const f = finding.finding;
    const parts = [
      f.title,
      f.severity,
      f.asset?.component,
      f.vulnerability?.cveId,
      f.vulnerability?.cweId,
    ].filter(Boolean);

    return parts.join('|');
  }
}

