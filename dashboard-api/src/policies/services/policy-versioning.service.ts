import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { Policy, PolicyVersion } from '../entities/policy.entity';

export interface VersionComparison {
  version1: string;
  version2: string;
  differences: {
    field: string;
    oldValue: any;
    newValue: any;
    changeType: 'added' | 'removed' | 'modified';
  }[];
  summary: {
    totalChanges: number;
    addedFields: number;
    removedFields: number;
    modifiedFields: number;
  };
}

export interface ImpactAnalysis {
  affectedApplications: string[];
  affectedTestResults: number;
  potentialViolations: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  recommendations: string[];
}

@Injectable()
export class PolicyVersioningService {
  constructor(
    private readonly moduleRef: ModuleRef,
  ) {}

  /**
   * Create a new version of a policy
   */
  createVersion(
    policy: Policy,
    changes: PolicyVersion['changes'],
    author?: string,
    notes?: string,
  ): PolicyVersion {
    const currentVersion = this.parseVersion(policy.version);
    const newVersionNumber = `${currentVersion.major}.${currentVersion.minor + 1}.0`;

    const newVersion: PolicyVersion = {
      version: newVersionNumber,
      status: policy.status,
      date: new Date(),
      author,
      changes,
      notes,
    };

    return newVersion;
  }

  /**
   * Get version history for a policy
   */
  getVersionHistory(policy: Policy): PolicyVersion[] {
    return [...policy.versions].sort((a, b) => 
      new Date(b.date).getTime() - new Date(a.date).getTime()
    );
  }

  /**
   * Get a specific version of a policy
   */
  getVersion(policy: Policy, version: string): PolicyVersion | null {
    return policy.versions.find(v => v.version === version) || null;
  }

  /**
   * Compare two versions of a policy
   */
  compareVersions(
    policy: Policy,
    version1: string,
    version2: string,
  ): VersionComparison {
    const v1 = this.getVersion(policy, version1);
    const v2 = this.getVersion(policy, version2);

    if (!v1 || !v2) {
      throw new NotFoundException(`One or both versions not found: ${version1}, ${version2}`);
    }

    // Get policy snapshots for each version (simplified - in real implementation, store snapshots)
    // For now, we'll compare the current policy state
    const differences: VersionComparison['differences'] = [];

    // Compare basic fields
    if (v1.status !== v2.status) {
      differences.push({
        field: 'status',
        oldValue: v1.status,
        newValue: v2.status,
        changeType: 'modified',
      });
    }

    // Compare changes arrays
    const v1Changes = v1.changes || [];
    const v2Changes = v2.changes || [];

    // Find added changes
    v2Changes.forEach(change => {
      if (!v1Changes.some(c => c.description === change.description && c.type === change.type)) {
        differences.push({
          field: `change:${change.type}`,
          oldValue: null,
          newValue: change.description,
          changeType: 'added',
        });
      }
    });

    // Find removed changes
    v1Changes.forEach(change => {
      if (!v2Changes.some(c => c.description === change.description && c.type === change.type)) {
        differences.push({
          field: `change:${change.type}`,
          oldValue: change.description,
          newValue: null,
          changeType: 'removed',
        });
      }
    });

    const summary = {
      totalChanges: differences.length,
      addedFields: differences.filter(d => d.changeType === 'added').length,
      removedFields: differences.filter(d => d.changeType === 'removed').length,
      modifiedFields: differences.filter(d => d.changeType === 'modified').length,
    };

    return {
      version1,
      version2,
      differences,
      summary,
    };
  }

  /**
   * Analyze impact of a policy version change
   */
  async analyzeImpact(
    policy: Policy,
    newVersion: PolicyVersion,
  ): Promise<ImpactAnalysis> {
    // Get affected applications
    const affectedApplications = policy.applicationId ? [policy.applicationId] : [];

    // Get test results that reference this policy
    // Note: TestResultsService doesn't have findAll(), so we estimate based on policy
    // In a real implementation, this would query test results by policy ID
    const affectedTestResults = 0; // Placeholder - would need to implement policy-based query

    // Estimate potential violations based on policy type and changes
    let potentialViolations = 0;
    const riskLevel = this.calculateRiskLevel(policy, newVersion);

    // Generate recommendations
    const recommendations: string[] = [];
    
    if (newVersion.changes.some(c => c.type === 'removed')) {
      recommendations.push('Review removed rules/conditions as they may affect existing access patterns');
    }
    
    if (newVersion.changes.some(c => c.type === 'added')) {
      recommendations.push('Test new rules/conditions in a staging environment before deployment');
    }

    if (riskLevel === 'high' || riskLevel === 'critical') {
      recommendations.push('Consider gradual rollout or feature flag for this policy change');
      recommendations.push('Monitor test results closely after deployment');
    }

    if (affectedTestResults > 0) {
      recommendations.push(`Re-run ${affectedTestResults} affected test(s) to validate policy changes`);
    }

    return {
      affectedApplications,
      affectedTestResults,
      potentialViolations,
      riskLevel,
      recommendations,
    };
  }

  /**
   * Calculate risk level for a policy version change
   */
  private calculateRiskLevel(
    policy: Policy,
    version: PolicyVersion,
  ): ImpactAnalysis['riskLevel'] {
    const changes = version.changes || [];
    
    // Critical: Removing rules or changing status to active
    if (changes.some(c => c.type === 'removed') || 
        (version.status === 'active' && policy.status !== 'active')) {
      return 'critical';
    }

    // High: Adding new rules or changing effect
    if (changes.some(c => c.type === 'added') && changes.length > 3) {
      return 'high';
    }

    // Medium: Modifying existing rules
    if (changes.some(c => c.type === 'changed')) {
      return 'medium';
    }

    // Low: Minor changes or fixes
    return 'low';
  }

  /**
   * Parse version string (e.g., "1.2.3") into components
   */
  private parseVersion(version: string): { major: number; minor: number; patch: number } {
    const parts = version.split('.').map(Number);
    return {
      major: parts[0] || 0,
      minor: parts[1] || 0,
      patch: parts[2] || 0,
    };
  }

  /**
   * Rollback policy to a specific version
   */
  rollbackToVersion(
    policy: Policy,
    targetVersion: string,
  ): { success: boolean; newVersion: string; message: string } {
    const targetVersionObj = this.getVersion(policy, targetVersion);
    
    if (!targetVersionObj) {
      throw new NotFoundException(`Version ${targetVersion} not found`);
    }

    if (targetVersionObj.version === policy.version) {
      throw new BadRequestException(`Policy is already at version ${targetVersion}`);
    }

    // Create a rollback version
    const currentVersion = this.parseVersion(policy.version);
    const rollbackVersion = `${currentVersion.major}.${currentVersion.minor + 1}.0`;

    const rollbackVersionObj: PolicyVersion = {
      version: rollbackVersion,
      status: targetVersionObj.status,
      date: new Date(),
      changes: [
        {
          type: 'fixed',
          description: `Rollback to version ${targetVersion}`,
        },
      ],
      notes: `Rolled back from version ${policy.version} to ${targetVersion}`,
    };

    return {
      success: true,
      newVersion: rollbackVersion,
      message: `Policy will be rolled back to version ${targetVersion}. New version ${rollbackVersion} created.`,
    };
  }
}

