/**
 * Schema Versioning and Migration
 * 
 * Handles versioning of the UnifiedFinding schema and provides migration
 * functions to convert between schema versions.
 */

import { UnifiedFinding } from './unified-finding-schema';

/**
 * Current schema version
 */
export const CURRENT_SCHEMA_VERSION = '1.0.0';

/**
 * Schema version metadata
 */
export interface SchemaVersion {
  version: string;
  releasedAt: Date;
  description: string;
  breakingChanges: string[];
  migrationNotes?: string;
}

/**
 * Schema version history
 */
export const SCHEMA_VERSIONS: SchemaVersion[] = [
  {
    version: '1.0.0',
    releasedAt: new Date('2024-01-01'),
    description: 'Initial unified finding schema with ECS compatibility',
    breakingChanges: [],
  },
];

/**
 * Versioned Unified Finding with schema version metadata
 */
export interface VersionedUnifiedFinding extends UnifiedFinding {
  _schema?: {
    version: string;
    migratedFrom?: string;
    migratedAt?: Date;
  };
}

/**
 * Migration function type
 */
export type MigrationFunction = (finding: any) => any;

/**
 * Migration registry
 * Maps from version to migration function
 */
const MIGRATIONS: Map<string, Map<string, MigrationFunction>> = new Map();

/**
 * Register a migration function
 */
export function registerMigration(
  fromVersion: string,
  toVersion: string,
  migration: MigrationFunction
): void {
  if (!MIGRATIONS.has(fromVersion)) {
    MIGRATIONS.set(fromVersion, new Map());
  }
  MIGRATIONS.get(fromVersion)!.set(toVersion, migration);
}

/**
 * Get migration path between versions
 */
function getMigrationPath(
  fromVersion: string,
  toVersion: string
): string[] {
  const versions = SCHEMA_VERSIONS.map(v => v.version).sort();
  const fromIndex = versions.indexOf(fromVersion);
  const toIndex = versions.indexOf(toVersion);

  if (fromIndex === -1 || toIndex === -1) {
    throw new Error(`Invalid schema version: ${fromVersion} or ${toVersion}`);
  }

  if (fromIndex === toIndex) {
    return [];
  }

  if (fromIndex < toIndex) {
    // Forward migration
    return versions.slice(fromIndex + 1, toIndex + 1);
  } else {
    // Backward migration (not typically supported, but path exists)
    return versions.slice(toIndex, fromIndex).reverse();
  }
}

/**
 * Migrate a finding from one schema version to another
 */
export function migrateFinding(
  finding: any,
  fromVersion: string,
  toVersion: string = CURRENT_SCHEMA_VERSION
): VersionedUnifiedFinding {
  if (fromVersion === toVersion) {
    return {
      ...finding,
      _schema: {
        version: toVersion,
      },
    };
  }

  const migrationPath = getMigrationPath(fromVersion, toVersion);
  let currentFinding = { ...finding };

  for (const targetVersion of migrationPath) {
    const fromVersionMap = MIGRATIONS.get(fromVersion);
    if (fromVersionMap) {
      const migration = fromVersionMap.get(targetVersion);
      if (migration) {
        currentFinding = migration(currentFinding);
        fromVersion = targetVersion;
      } else {
        // Try to find a chain migration
        // For now, we'll use identity migration if no specific migration exists
        console.warn(`No direct migration from ${fromVersion} to ${targetVersion}, using identity`);
      }
    }
  }

  return {
    ...currentFinding,
    _schema: {
      version: toVersion,
      migratedFrom: finding._schema?.version || fromVersion,
      migratedAt: new Date(),
    },
  };
}

/**
 * Detect schema version from a finding
 */
export function detectSchemaVersion(finding: any): string {
  // Check explicit version
  if (finding._schema?.version) {
    return finding._schema.version;
  }

  // Detect version based on schema structure
  // Version 1.0.0 has these characteristics:
  if (finding.event && finding.asset && finding.remediation) {
    return '1.0.0';
  }

  // Legacy format detection (pre-1.0.0)
  if (finding.vulnerability && !finding.event) {
    return '0.9.0'; // Hypothetical legacy version
  }

  // Default to current version if structure matches
  return CURRENT_SCHEMA_VERSION;
}

/**
 * Normalize finding to current schema version
 */
export function normalizeToCurrentVersion(finding: any): VersionedUnifiedFinding {
  const detectedVersion = detectSchemaVersion(finding);
  return migrateFinding(finding, detectedVersion, CURRENT_SCHEMA_VERSION);
}

/**
 * Validate finding against a specific schema version
 */
export function validateSchemaVersion(
  finding: any,
  version: string = CURRENT_SCHEMA_VERSION
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (version === '1.0.0') {
    // Required fields for v1.0.0
    if (!finding.id) {
      errors.push('Missing required field: id');
    }
    if (!finding.event) {
      errors.push('Missing required field: event');
    } else {
      if (!finding.event.kind) {
        errors.push('Missing required field: event.kind');
      }
      if (!finding.event.category) {
        errors.push('Missing required field: event.category');
      }
      if (!finding.event.type) {
        errors.push('Missing required field: event.type');
      }
    }
    if (!finding.source) {
      errors.push('Missing required field: source');
    }
    if (!finding.scannerId) {
      errors.push('Missing required field: scannerId');
    }
    if (!finding.scannerFindingId) {
      errors.push('Missing required field: scannerFindingId');
    }
    if (!finding.title) {
      errors.push('Missing required field: title');
    }
    if (!finding.description) {
      errors.push('Missing required field: description');
    }
    if (!finding.severity) {
      errors.push('Missing required field: severity');
    }
    if (!finding.asset) {
      errors.push('Missing required field: asset');
    } else {
      if (!finding.asset.type) {
        errors.push('Missing required field: asset.type');
      }
    }
    if (!finding.remediation) {
      errors.push('Missing required field: remediation');
    } else {
      if (!finding.remediation.description) {
        errors.push('Missing required field: remediation.description');
      }
      if (!Array.isArray(finding.remediation.steps)) {
        errors.push('Missing required field: remediation.steps (must be array)');
      }
      if (!Array.isArray(finding.remediation.references)) {
        errors.push('Missing required field: remediation.references (must be array)');
      }
    }
    if (!finding.status) {
      errors.push('Missing required field: status');
    }
    if (typeof finding.riskScore !== 'number') {
      errors.push('Missing required field: riskScore (must be number)');
    }
    if (!finding.createdAt) {
      errors.push('Missing required field: createdAt');
    }
    if (!finding.updatedAt) {
      errors.push('Missing required field: updatedAt');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Get schema version information
 */
export function getSchemaVersion(version: string): SchemaVersion | undefined {
  return SCHEMA_VERSIONS.find(v => v.version === version);
}

/**
 * Get all available schema versions
 */
export function getAvailableVersions(): string[] {
  return SCHEMA_VERSIONS.map(v => v.version);
}

/**
 * Check if migration is needed
 */
export function needsMigration(finding: any): boolean {
  const detectedVersion = detectSchemaVersion(finding);
  return detectedVersion !== CURRENT_SCHEMA_VERSION;
}

/**
 * Batch migrate findings
 */
export function migrateFindings(
  findings: any[],
  fromVersion?: string
): VersionedUnifiedFinding[] {
  return findings.map(finding => {
    if (fromVersion) {
      return migrateFinding(finding, fromVersion);
    }
    return normalizeToCurrentVersion(finding);
  });
}

