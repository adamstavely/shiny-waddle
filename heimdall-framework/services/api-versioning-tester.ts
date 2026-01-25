/**
 * API Versioning Security Tester
 * 
 * Tests API version deprecation, access control, backward compatibility, and migration security
 */

import { User } from '../core/types';

export interface APIVersion {
  version: string;
  endpoint: string;
  deprecated: boolean;
  deprecationDate?: Date;
  sunsetDate?: Date;
  accessControl: AccessControlPolicy;
}

export interface AccessControlPolicy {
  requiredRoles?: string[];
  requiredPermissions?: string[];
  rateLimit?: {
    requests: number;
    window: number; // seconds
  };
}

export interface APIVersioningTestResult {
  passed: boolean;
  version: string;
  issues: Array<{
    type: 'no-deprecation-policy' | 'insecure-deprecated' | 'no-migration-path' | 'version-conflict';
    severity: 'critical' | 'high' | 'medium' | 'low';
    message: string;
  }>;
  backwardCompatibility: CompatibilityResult;
}

export interface CompatibilityResult {
  compatible: boolean;
  breakingChanges: string[];
  warnings: string[];
}

export interface AccessControlResult {
  allowed: boolean;
  user: User;
  version: string;
  reason?: string;
}

export interface MigrationResult {
  canMigrate: boolean;
  migrationPath?: string;
  issues: string[];
  estimatedEffort?: string;
}

export interface DocumentationResult {
  documented: boolean;
  missingSections: string[];
  securityNotes: string[];
}

export class APIVersioningTester {
  /**
   * Test version deprecation
   */
  async testVersionDeprecation(
    version: APIVersion
  ): Promise<APIVersioningTestResult> {
    const issues: APIVersioningTestResult['issues'] = [];
    const backwardCompatibility: CompatibilityResult = {
      compatible: true,
      breakingChanges: [],
      warnings: [],
    };

    // Check if deprecated version has deprecation policy
    if (version.deprecated) {
      if (!version.deprecationDate) {
        issues.push({
          type: 'no-deprecation-policy',
          severity: 'high',
          message: 'Deprecated version missing deprecation date',
        });
      }

      if (!version.sunsetDate) {
        issues.push({
          type: 'no-deprecation-policy',
          severity: 'medium',
          message: 'Deprecated version missing sunset date',
        });
      } else {
        // Check if sunset date is in the past
        if (version.sunsetDate < new Date()) {
          issues.push({
            type: 'insecure-deprecated',
            severity: 'critical',
            message: 'Deprecated version past sunset date but still accessible',
          });
        }
      }

      // Check if deprecated version has weaker security
      if (!version.accessControl.requiredRoles || version.accessControl.requiredRoles.length === 0) {
        issues.push({
          type: 'insecure-deprecated',
          severity: 'high',
          message: 'Deprecated version has no access control requirements',
        });
      }
    }

    // Check for migration path
    if (version.deprecated && !version.endpoint.includes('/v2') && !version.endpoint.includes('/v3')) {
      issues.push({
        type: 'no-migration-path',
        severity: 'medium',
        message: 'No clear migration path to newer version',
      });
    }

    return {
      passed: issues.filter(i => i.severity === 'critical' || i.severity === 'high').length === 0,
      version: version.version,
      issues,
      backwardCompatibility,
    };
  }

  /**
   * Validate version access control
   */
  async validateVersionAccessControl(
    version: APIVersion,
    user: User
  ): Promise<AccessControlResult> {
    let allowed = true;
    let reason: string | undefined;

    // Check role requirements
    if (version.accessControl.requiredRoles && version.accessControl.requiredRoles.length > 0) {
      if (!version.accessControl.requiredRoles.includes(user.role)) {
        allowed = false;
        reason = `User role ${user.role} not in required roles: ${version.accessControl.requiredRoles.join(', ')}`;
      }
    }

    // Check permission requirements
    if (version.accessControl.requiredPermissions && version.accessControl.requiredPermissions.length > 0) {
      const userPermissions = user.attributes?.permissions || [];
      const missingPermissions = version.accessControl.requiredPermissions.filter(
        p => !userPermissions.includes(p)
      );

      if (missingPermissions.length > 0) {
        allowed = false;
        reason = `Missing required permissions: ${missingPermissions.join(', ')}`;
      }
    }

    return {
      allowed,
      user,
      version: version.version,
      reason,
    };
  }

  /**
   * Test backward compatibility
   */
  async testBackwardCompatibility(
    oldVersion: string,
    newVersion: string
  ): Promise<CompatibilityResult> {
    const breakingChanges: string[] = [];
    const warnings: string[] = [];

    // Parse version numbers
    const oldVersionNum = this.parseVersion(oldVersion);
    const newVersionNum = this.parseVersion(newVersion);

    // Check if it's a major version change (breaking)
    if (oldVersionNum.major !== newVersionNum.major) {
      breakingChanges.push('Major version change - breaking changes expected');
    }

    // Check if it's a minor version change (backward compatible)
    if (oldVersionNum.major === newVersionNum.major && oldVersionNum.minor !== newVersionNum.minor) {
      warnings.push('Minor version change - should be backward compatible');
    }

    // Check if it's a patch version change (should be fully compatible)
    if (
      oldVersionNum.major === newVersionNum.major &&
      oldVersionNum.minor === newVersionNum.minor &&
      oldVersionNum.patch !== newVersionNum.patch
    ) {
      // Patch versions should be fully compatible
    }

    return {
      compatible: breakingChanges.length === 0,
      breakingChanges,
      warnings,
    };
  }

  /**
   * Test version migration
   */
  async testVersionMigration(
    version: APIVersion
  ): Promise<MigrationResult> {
    const issues: string[] = [];
    let canMigrate = true;

    if (!version.deprecated) {
      return {
        canMigrate: false,
        issues: ['Version is not deprecated, migration not needed'],
      };
    }

    // Check if there's a newer version available
    const currentVersion = this.parseVersion(version.version);
    const hasNewerVersion = currentVersion.major < 10; // Simplified check

    if (!hasNewerVersion) {
      issues.push('No newer version available for migration');
      canMigrate = false;
    }

    // Check migration documentation
    if (!version.endpoint.includes('/migration') && !version.endpoint.includes('/upgrade')) {
      issues.push('No migration documentation or endpoint found');
    }

    // Estimate migration effort
    let estimatedEffort = 'Low';
    if (currentVersion.major < this.parseVersion('v2').major) {
      estimatedEffort = 'High';
    } else if (currentVersion.major < this.parseVersion('v3').major) {
      estimatedEffort = 'Medium';
    }

    return {
      canMigrate,
      migrationPath: hasNewerVersion ? `Migrate to v${currentVersion.major + 1}` : undefined,
      issues,
      estimatedEffort,
    };
  }

  /**
   * Validate version documentation
   */
  async validateVersionDocumentation(
    version: APIVersion
  ): Promise<DocumentationResult> {
    const missingSections: string[] = [];
    const securityNotes: string[] = [];

    // Check for required documentation sections
    if (version.deprecated && !version.deprecationDate) {
      missingSections.push('Deprecation date');
    }

    if (version.deprecated && !version.sunsetDate) {
      missingSections.push('Sunset date');
    }

    // Check for security notes
    if (version.deprecated) {
      securityNotes.push('Deprecated versions may have security vulnerabilities');
    }

    if (!version.accessControl.requiredRoles || version.accessControl.requiredRoles.length === 0) {
      securityNotes.push('Version has no access control requirements');
    }

    return {
      documented: missingSections.length === 0,
      missingSections,
      securityNotes,
    };
  }

  /**
   * Parse version string (e.g., "v1.2.3" or "1.2.3")
   */
  private parseVersion(version: string): { major: number; minor: number; patch: number } {
    const cleaned = version.replace(/^v/i, '');
    const parts = cleaned.split('.').map(Number);

    return {
      major: parts[0] || 0,
      minor: parts[1] || 0,
      patch: parts[2] || 0,
    };
  }
}

