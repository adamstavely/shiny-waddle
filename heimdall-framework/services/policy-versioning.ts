/**
 * Policy Versioning & Rollback Service
 * 
 * Manages policy versions, changes, and rollback capabilities
 */

import { ABACPolicy } from '../core/types';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface PolicyVersion {
  version: string;
  timestamp: Date;
  policies: ABACPolicy[];
  changeDescription?: string;
  author?: string;
  tags?: string[];
}

export interface PolicyChange {
  type: 'added' | 'modified' | 'deleted';
  policyId: string;
  oldPolicy?: ABACPolicy;
  newPolicy?: ABACPolicy;
  description?: string;
}

export interface PolicyDiff {
  version1: string;
  version2: string;
  changes: PolicyChange[];
  summary: {
    added: number;
    modified: number;
    deleted: number;
  };
}

export class PolicyVersioning {
  private versionsDir: string;

  constructor(versionsDir: string = './policies/versions') {
    this.versionsDir = versionsDir;
  }

  /**
   * Create a new policy version
   */
  async createVersion(
    policies: ABACPolicy[],
    changeDescription?: string,
    author?: string,
    tags?: string[]
  ): Promise<PolicyVersion> {
    const version = this.generateVersion();
    const timestamp = new Date();

    const versionData: PolicyVersion = {
      version,
      timestamp,
      policies,
      changeDescription,
      author,
      tags,
    };

    // Save version
    await this.saveVersion(versionData);

    // Update current version pointer
    await this.updateCurrentVersion(version);

    return versionData;
  }

  /**
   * Get policy version
   */
  async getVersion(version: string): Promise<PolicyVersion | null> {
    try {
      const filePath = path.join(this.versionsDir, `${version}.json`);
      const content = await fs.readFile(filePath, 'utf-8');
      return JSON.parse(content);
    } catch (error) {
      return null;
    }
  }

  /**
   * Get current version
   */
  async getCurrentVersion(): Promise<PolicyVersion | null> {
    try {
      const currentPath = path.join(this.versionsDir, 'current.json');
      const content = await fs.readFile(currentPath, 'utf-8');
      const { version } = JSON.parse(content);
      return this.getVersion(version);
    } catch (error) {
      return null;
    }
  }

  /**
   * List all versions
   */
  async listVersions(): Promise<PolicyVersion[]> {
    try {
      const files = await fs.readdir(this.versionsDir);
      const versionFiles = files.filter(f => f.endsWith('.json') && f !== 'current.json');
      
      const versions: PolicyVersion[] = [];
      for (const file of versionFiles) {
        const version = file.replace('.json', '');
        const versionData = await this.getVersion(version);
        if (versionData) {
          versions.push(versionData);
        }
      }

      return versions.sort((a, b) => 
        b.timestamp.getTime() - a.timestamp.getTime()
      );
    } catch (error) {
      return [];
    }
  }

  /**
   * Rollback to a previous version
   */
  async rollback(version: string): Promise<PolicyVersion> {
    const targetVersion = await this.getVersion(version);
    if (!targetVersion) {
      throw new Error(`Version ${version} not found`);
    }

    // Create a new version with the rolled-back policies
    const rollbackVersion = await this.createVersion(
      targetVersion.policies,
      `Rollback to version ${version}`,
      'system'
    );

    return rollbackVersion;
  }

  /**
   * Compare two policy versions
   */
  async diff(version1: string, version2: string): Promise<PolicyDiff> {
    const v1 = await this.getVersion(version1);
    const v2 = await this.getVersion(version2);

    if (!v1 || !v2) {
      throw new Error('One or both versions not found');
    }

    const changes: PolicyChange[] = [];
    const v1Policies = new Map(v1.policies.map(p => [p.id, p]));
    const v2Policies = new Map(v2.policies.map(p => [p.id, p]));

    // Find added and modified policies
    for (const [id, policy] of v2Policies) {
      if (!v1Policies.has(id)) {
        changes.push({
          type: 'added',
          policyId: id,
          newPolicy: policy,
        });
      } else {
        const oldPolicy = v1Policies.get(id)!;
        if (!this.policiesEqual(oldPolicy, policy)) {
          changes.push({
            type: 'modified',
            policyId: id,
            oldPolicy,
            newPolicy: policy,
          });
        }
      }
    }

    // Find deleted policies
    for (const [id, policy] of v1Policies) {
      if (!v2Policies.has(id)) {
        changes.push({
          type: 'deleted',
          policyId: id,
          oldPolicy: policy,
        });
      }
    }

    return {
      version1,
      version2,
      changes,
      summary: {
        added: changes.filter(c => c.type === 'added').length,
        modified: changes.filter(c => c.type === 'modified').length,
        deleted: changes.filter(c => c.type === 'deleted').length,
      },
    };
  }

  /**
   * Analyze impact of policy changes
   */
  async analyzeChangeImpact(
    oldVersion: string,
    newVersion: string
  ): Promise<{
    breakingChanges: PolicyChange[];
    warnings: string[];
    affectedResources: string[];
  }> {
    const diff = await this.diff(oldVersion, newVersion);
    const breakingChanges: PolicyChange[] = [];
    const warnings: string[] = [];
    const affectedResources = new Set<string>();

    for (const change of diff.changes) {
      if (change.type === 'deleted') {
        breakingChanges.push(change);
        warnings.push(`Policy ${change.policyId} was deleted - may break existing access`);
      } else if (change.type === 'modified') {
        // Check if modification is breaking
        if (this.isBreakingChange(change.oldPolicy!, change.newPolicy!)) {
          breakingChanges.push(change);
          warnings.push(`Policy ${change.policyId} has breaking changes`);
        }

        // Extract affected resources
        if (change.newPolicy) {
          this.extractResources(change.newPolicy, affectedResources);
        }
      } else if (change.type === 'added') {
        if (change.newPolicy) {
          this.extractResources(change.newPolicy, affectedResources);
        }
      }
    }

    return {
      breakingChanges,
      warnings,
      affectedResources: Array.from(affectedResources),
    };
  }

  /**
   * Check if policy change is breaking
   */
  private isBreakingChange(oldPolicy: ABACPolicy, newPolicy: ABACPolicy): boolean {
    // Change from allow to deny is breaking
    if (oldPolicy.effect === 'allow' && newPolicy.effect === 'deny') {
      return true;
    }

    // Removing conditions that were previously required
    if (newPolicy.conditions.length < oldPolicy.conditions.length) {
      return true;
    }

    // Increasing priority of deny policies
    if (newPolicy.effect === 'deny' && 
        (newPolicy.priority || 0) > (oldPolicy.priority || 0)) {
      return true;
    }

    return false;
  }

  /**
   * Extract resources from policy
   */
  private extractResources(policy: ABACPolicy, resources: Set<string>): void {
    for (const condition of policy.conditions) {
      if (condition.attribute.startsWith('resource.')) {
        const resourceType = condition.attribute.split('.')[1];
        resources.add(resourceType);
      }
    }
  }

  /**
   * Check if two policies are equal
   */
  private policiesEqual(p1: ABACPolicy, p2: ABACPolicy): boolean {
    return JSON.stringify(p1) === JSON.stringify(p2);
  }

  /**
   * Generate version string
   */
  private generateVersion(): string {
    const now = new Date();
    const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, -5);
    return `v${timestamp}`;
  }

  /**
   * Save version to file
   */
  private async saveVersion(version: PolicyVersion): Promise<void> {
    await fs.mkdir(this.versionsDir, { recursive: true });
    const filePath = path.join(this.versionsDir, `${version.version}.json`);
    await fs.writeFile(filePath, JSON.stringify(version, null, 2));
  }

  /**
   * Update current version pointer
   */
  private async updateCurrentVersion(version: string): Promise<void> {
    await fs.mkdir(this.versionsDir, { recursive: true });
    const currentPath = path.join(this.versionsDir, 'current.json');
    await fs.writeFile(currentPath, JSON.stringify({ version }, null, 2));
  }

  /**
   * Get version history
   */
  async getVersionHistory(limit?: number): Promise<PolicyVersion[]> {
    const versions = await this.listVersions();
    return limit ? versions.slice(0, limit) : versions;
  }

  /**
   * Tag a version
   */
  async tagVersion(version: string, tags: string[]): Promise<void> {
    const versionData = await this.getVersion(version);
    if (!versionData) {
      throw new Error(`Version ${version} not found`);
    }

    versionData.tags = [...(versionData.tags || []), ...tags];
    await this.saveVersion(versionData);
  }

  /**
   * Get versions by tag
   */
  async getVersionsByTag(tag: string): Promise<PolicyVersion[]> {
    const versions = await this.listVersions();
    return versions.filter(v => v.tags?.includes(tag));
  }
}

