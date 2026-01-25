/**
 * Schema Migration Functions
 * 
 * Migration functions to convert findings between schema versions.
 * These functions handle breaking changes and field transformations.
 */

import { registerMigration } from './schema-versioning';
import { UnifiedFinding } from './unified-finding-schema';

/**
 * Example migration: 0.9.0 -> 1.0.0
 * This is a hypothetical migration for demonstration purposes
 */
function migrate_0_9_0_to_1_0_0(finding: any): UnifiedFinding {
  // In version 0.9.0, findings might have had a different structure
  // This migration converts them to 1.0.0 format
  
  const migrated: any = {
    ...finding,
  };

  // Ensure event object exists
  if (!migrated.event) {
    migrated.event = {
      kind: 'event',
      category: 'security',
      type: 'vulnerability',
      action: 'detected',
      severity: 0,
    };
  }

  // Map old severity format to new event.severity
  if (migrated.severity && !migrated.event.severity) {
    const severityMap: Record<string, number> = {
      'critical': 900,
      'high': 700,
      'medium': 500,
      'low': 300,
      'info': 100,
    };
    migrated.event.severity = severityMap[migrated.severity] || 500;
  }

  // Ensure asset structure
  if (!migrated.asset) {
    migrated.asset = {
      type: 'application',
    };
  } else if (typeof migrated.asset === 'string') {
    // Old format: asset was just a string
    migrated.asset = {
      type: migrated.asset as any,
    };
  }

  // Ensure remediation structure
  if (!migrated.remediation) {
    migrated.remediation = {
      description: migrated.description || 'No remediation provided',
      steps: [],
      references: [],
    };
  } else if (typeof migrated.remediation === 'string') {
    // Old format: remediation was just a string
    migrated.remediation = {
      description: migrated.remediation,
      steps: [],
      references: [],
    };
  }

  // Ensure dates are Date objects
  if (migrated.createdAt && typeof migrated.createdAt === 'string') {
    migrated.createdAt = new Date(migrated.createdAt);
  }
  if (migrated.updatedAt && typeof migrated.updatedAt === 'string') {
    migrated.updatedAt = new Date(migrated.updatedAt);
  }
  if (migrated.detectedAt && typeof migrated.detectedAt === 'string') {
    migrated.detectedAt = new Date(migrated.detectedAt);
  }
  if (migrated.resolvedAt && typeof migrated.resolvedAt === 'string') {
    migrated.resolvedAt = new Date(migrated.resolvedAt);
  }

  // Ensure riskScore exists
  if (typeof migrated.riskScore !== 'number') {
    // Calculate risk score from severity if missing
    const severityScores: Record<string, number> = {
      'critical': 90,
      'high': 70,
      'medium': 50,
      'low': 30,
      'info': 10,
    };
    migrated.riskScore = severityScores[migrated.severity] || 50;
  }

  // Ensure status exists
  if (!migrated.status) {
    migrated.status = 'open';
  }

  // Ensure confidence exists
  if (!migrated.confidence) {
    migrated.confidence = 'tentative';
  }

  return migrated as UnifiedFinding;
}

/**
 * Register all migrations
 */
export function registerAllMigrations(): void {
  // Register 0.9.0 -> 1.0.0 migration
  registerMigration('0.9.0', '1.0.0', migrate_0_9_0_to_1_0_0);
  
  // Future migrations can be registered here:
  // registerMigration('1.0.0', '1.1.0', migrate_1_0_0_to_1_1_0);
  // registerMigration('1.1.0', '2.0.0', migrate_1_1_0_to_2_0_0);
}

// Auto-register migrations when module is loaded
registerAllMigrations();

