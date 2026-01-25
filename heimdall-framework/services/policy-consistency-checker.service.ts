/**
 * Policy Consistency Checker Service
 * 
 * Compares policies across regions, detects inconsistencies,
 * and reports differences
 */

import { RegionConfig } from './distributed-systems-tester';

export interface PolicyDefinition {
  id: string;
  name: string;
  version: string;
  rules?: any[];
  conditions?: any[];
  effect?: 'allow' | 'deny';
  priority?: number;
  metadata?: Record<string, any>;
}

export interface PolicyConsistencyCheckRequest {
  regions: string[]; // Region IDs to check
  policyIds?: string[]; // Specific policies to check, or all if not specified
  checkTypes?: PolicyConsistencyCheckType[];
}

export type PolicyConsistencyCheckType =
  | 'version'
  | 'configuration'
  | 'evaluation';

export interface PolicyInconsistency {
  policyId: string;
  policyName: string;
  inconsistencyType: PolicyConsistencyCheckType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regions: string[];
  differences: PolicyDifference[];
  recommendation?: string;
}

export interface PolicyDifference {
  field: string;
  region1: {
    id: string;
    value: any;
  };
  region2: {
    id: string;
    value: any;
  };
  description: string;
}

export interface PolicyConsistencyReport {
  id: string;
  timestamp: Date;
  regionsChecked: string[];
  policiesChecked: string[];
  consistent: boolean;
  inconsistencies: PolicyInconsistency[];
  summary: {
    totalPolicies: number;
    consistentPolicies: number;
    inconsistentPolicies: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
  };
  recommendations: string[];
}

export class PolicyConsistencyChecker {
  /**
   * Check policy consistency across regions
   */
  async checkConsistency(
    regions: RegionConfig[],
    request: PolicyConsistencyCheckRequest
  ): Promise<PolicyConsistencyReport> {
    const reportId = `consistency-${Date.now()}`;
    const timestamp = new Date();
    const inconsistencies: PolicyInconsistency[] = [];
    const checkTypes = request.checkTypes || ['version', 'configuration', 'evaluation'];

    // Get regions to check
    const regionsToCheck = regions.filter(r =>
      request.regions.length === 0 || request.regions.includes(r.id)
    );

    if (regionsToCheck.length < 2) {
      throw new Error('At least 2 regions are required for consistency checking');
    }

    // Fetch policies from each region
    const regionPolicies: Map<string, PolicyDefinition[]> = new Map();
    for (const region of regionsToCheck) {
      const policies = await this.fetchPoliciesFromRegion(region, request.policyIds);
      regionPolicies.set(region.id, policies);
    }

    // Get all unique policy IDs
    const allPolicyIds = new Set<string>();
    regionPolicies.forEach(policies => {
      policies.forEach(policy => allPolicyIds.add(policy.id));
    });

    // Check consistency for each policy
    for (const policyId of allPolicyIds) {
      const policiesByRegion = new Map<string, PolicyDefinition>();
      regionPolicies.forEach((policies, regionId) => {
        const policy = policies.find(p => p.id === policyId);
        if (policy) {
          policiesByRegion.set(regionId, policy);
        }
      });

      if (policiesByRegion.size < 2) {
        // Policy doesn't exist in all regions
        inconsistencies.push({
          policyId,
          policyName: policiesByRegion.values().next().value?.name || policyId,
          inconsistencyType: 'configuration',
          severity: 'high',
          regions: Array.from(policiesByRegion.keys()),
          differences: [
            {
              field: 'existence',
              region1: {
                id: regionsToCheck[0].id,
                value: policiesByRegion.has(regionsToCheck[0].id),
              },
              region2: {
                id: regionsToCheck[1].id,
                value: policiesByRegion.has(regionsToCheck[1].id),
              },
              description: 'Policy exists in some regions but not others',
            },
          ],
          recommendation: 'Ensure policy is deployed to all regions',
        });
        continue;
      }

      // Check version consistency
      if (checkTypes.includes('version')) {
        const versionInconsistencies = this.checkVersionConsistency(
          policyId,
          policiesByRegion,
          regionsToCheck
        );
        if (versionInconsistencies.length > 0) {
          inconsistencies.push(...versionInconsistencies);
        }
      }

      // Check configuration consistency
      if (checkTypes.includes('configuration')) {
        const configInconsistencies = this.checkConfigurationConsistency(
          policyId,
          policiesByRegion,
          regionsToCheck
        );
        if (configInconsistencies.length > 0) {
          inconsistencies.push(...configInconsistencies);
        }
      }

      // Check evaluation consistency
      if (checkTypes.includes('evaluation')) {
        const evalInconsistencies = await this.checkEvaluationConsistency(
          policyId,
          policiesByRegion,
          regionsToCheck
        );
        if (evalInconsistencies.length > 0) {
          inconsistencies.push(...evalInconsistencies);
        }
      }
    }

    // Generate summary
    const summary = this.generateSummary(inconsistencies, allPolicyIds.size);
    const recommendations = this.generateRecommendations(inconsistencies);

    return {
      id: reportId,
      timestamp,
      regionsChecked: regionsToCheck.map(r => r.id),
      policiesChecked: Array.from(allPolicyIds),
      consistent: inconsistencies.length === 0,
      inconsistencies,
      summary,
      recommendations,
    };
  }

  /**
   * Check version consistency
   */
  private checkVersionConsistency(
    policyId: string,
    policiesByRegion: Map<string, PolicyDefinition>,
    regions: RegionConfig[]
  ): PolicyInconsistency[] {
    const inconsistencies: PolicyInconsistency[] = [];
    const versions = new Map<string, string>();

    policiesByRegion.forEach((policy, regionId) => {
      versions.set(regionId, policy.version);
    });

    const uniqueVersions = new Set(versions.values());
    if (uniqueVersions.size > 1) {
      const differences: PolicyDifference[] = [];
      const versionArray = Array.from(versions.entries());

      for (let i = 0; i < versionArray.length; i++) {
        for (let j = i + 1; j < versionArray.length; j++) {
          const [region1Id, version1] = versionArray[i];
          const [region2Id, version2] = versionArray[j];

          if (version1 !== version2) {
            differences.push({
              field: 'version',
              region1: { id: region1Id, value: version1 },
              region2: { id: region2Id, value: version2 },
              description: `Version mismatch: ${version1} vs ${version2}`,
            });
          }
        }
      }

      if (differences.length > 0) {
        inconsistencies.push({
          policyId,
          policyName: policiesByRegion.values().next().value?.name || policyId,
          inconsistencyType: 'version',
          severity: 'high',
          regions: Array.from(versions.keys()),
          differences,
          recommendation: 'Synchronize policy versions across all regions',
        });
      }
    }

    return inconsistencies;
  }

  /**
   * Check configuration consistency
   */
  private checkConfigurationConsistency(
    policyId: string,
    policiesByRegion: Map<string, PolicyDefinition>,
    regions: RegionConfig[]
  ): PolicyInconsistency[] {
    const inconsistencies: PolicyInconsistency[] = [];
    const differences: PolicyDifference[] = [];

    const policyArray = Array.from(policiesByRegion.entries());
    if (policyArray.length < 2) {
      return inconsistencies;
    }

    const [firstRegionId, firstPolicy] = policyArray[0];

    // Compare each region's policy with the first one
    for (let i = 1; i < policyArray.length; i++) {
      const [regionId, policy] = policyArray[i];

      // Compare rules
      const rules1 = JSON.stringify(firstPolicy.rules || []);
      const rules2 = JSON.stringify(policy.rules || []);
      if (rules1 !== rules2) {
        differences.push({
          field: 'rules',
          region1: { id: firstRegionId, value: firstPolicy.rules },
          region2: { id: regionId, value: policy.rules },
          description: 'Policy rules differ between regions',
        });
      }

      // Compare conditions
      const conditions1 = JSON.stringify(firstPolicy.conditions || []);
      const conditions2 = JSON.stringify(policy.conditions || []);
      if (conditions1 !== conditions2) {
        differences.push({
          field: 'conditions',
          region1: { id: firstRegionId, value: firstPolicy.conditions },
          region2: { id: regionId, value: policy.conditions },
          description: 'Policy conditions differ between regions',
        });
      }

      // Compare effect
      if (firstPolicy.effect !== policy.effect) {
        differences.push({
          field: 'effect',
          region1: { id: firstRegionId, value: firstPolicy.effect },
          region2: { id: regionId, value: policy.effect },
          description: `Effect mismatch: ${firstPolicy.effect} vs ${policy.effect}`,
        });
      }

      // Compare priority
      if (firstPolicy.priority !== policy.priority) {
        differences.push({
          field: 'priority',
          region1: { id: firstRegionId, value: firstPolicy.priority },
          region2: { id: regionId, value: policy.priority },
          description: `Priority mismatch: ${firstPolicy.priority} vs ${policy.priority}`,
        });
      }
    }

    if (differences.length > 0) {
      const severity = differences.some(d => d.field === 'effect') ? 'critical' : 'high';
      inconsistencies.push({
        policyId,
        policyName: firstPolicy.name,
        inconsistencyType: 'configuration',
        severity,
        regions: Array.from(policiesByRegion.keys()),
        differences,
        recommendation: 'Ensure policy configuration is identical across all regions',
      });
    }

    return inconsistencies;
  }

  /**
   * Check evaluation consistency
   */
  private async checkEvaluationConsistency(
    policyId: string,
    policiesByRegion: Map<string, PolicyDefinition>,
    regions: RegionConfig[]
  ): Promise<PolicyInconsistency[]> {
    // This would test policy evaluation with sample requests
    // to ensure policies produce consistent results
    // For now, return empty array as this requires actual policy evaluation
    return [];
  }

  /**
   * Fetch policies from a region
   */
  private async fetchPoliciesFromRegion(
    region: RegionConfig,
    policyIds?: string[]
  ): Promise<PolicyDefinition[]> {
    // In a real implementation, this would fetch policies from the region's API
    // For now, return empty array
    if (region.pdpEndpoint) {
      try {
        const response = await fetch(`${region.pdpEndpoint}/policies`, {
          headers: {
            ...(region.credentials?.token
              ? { Authorization: `Bearer ${region.credentials.token}` }
              : {}),
          },
        });

        if (response.ok) {
          const policies = await response.json();
          if (policyIds && policyIds.length > 0) {
            return policies.filter((p: PolicyDefinition) => policyIds.includes(p.id));
          }
          return policies;
        }
      } catch (error) {
        // If fetch fails, return empty array
        console.warn(`Failed to fetch policies from region ${region.id}:`, error);
      }
    }

    return [];
  }

  /**
   * Generate summary statistics
   */
  private generateSummary(
    inconsistencies: PolicyInconsistency[],
    totalPolicies: number
  ): PolicyConsistencyReport['summary'] {
    const inconsistentPolicyIds = new Set(
      inconsistencies.map(i => i.policyId)
    );

    return {
      totalPolicies,
      consistentPolicies: totalPolicies - inconsistentPolicyIds.size,
      inconsistentPolicies: inconsistentPolicyIds.size,
      criticalIssues: inconsistencies.filter(i => i.severity === 'critical').length,
      highIssues: inconsistencies.filter(i => i.severity === 'high').length,
      mediumIssues: inconsistencies.filter(i => i.severity === 'medium').length,
      lowIssues: inconsistencies.filter(i => i.severity === 'low').length,
    };
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    inconsistencies: PolicyInconsistency[]
  ): string[] {
    const recommendations: string[] = [];

    if (inconsistencies.length === 0) {
      return ['All policies are consistent across regions'];
    }

    const criticalIssues = inconsistencies.filter(i => i.severity === 'critical');
    if (criticalIssues.length > 0) {
      recommendations.push(
        `Address ${criticalIssues.length} critical inconsistency(ies) immediately`
      );
    }

    const versionIssues = inconsistencies.filter(i => i.inconsistencyType === 'version');
    if (versionIssues.length > 0) {
      recommendations.push('Synchronize policy versions across all regions');
    }

    const configIssues = inconsistencies.filter(i => i.inconsistencyType === 'configuration');
    if (configIssues.length > 0) {
      recommendations.push('Review and align policy configurations across regions');
    }

    // Add specific recommendations from inconsistencies
    inconsistencies.forEach(inconsistency => {
      if (inconsistency.recommendation) {
        if (!recommendations.includes(inconsistency.recommendation)) {
          recommendations.push(inconsistency.recommendation);
        }
      }
    });

    return recommendations;
  }
}
