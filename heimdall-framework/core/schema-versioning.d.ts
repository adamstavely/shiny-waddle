import { UnifiedFinding } from './unified-finding-schema';
export declare const CURRENT_SCHEMA_VERSION = "1.0.0";
export interface SchemaVersion {
    version: string;
    releasedAt: Date;
    description: string;
    breakingChanges: string[];
    migrationNotes?: string;
}
export declare const SCHEMA_VERSIONS: SchemaVersion[];
export interface VersionedUnifiedFinding extends UnifiedFinding {
    _schema?: {
        version: string;
        migratedFrom?: string;
        migratedAt?: Date;
    };
}
export type MigrationFunction = (finding: any) => any;
export declare function registerMigration(fromVersion: string, toVersion: string, migration: MigrationFunction): void;
export declare function migrateFinding(finding: any, fromVersion: string, toVersion?: string): VersionedUnifiedFinding;
export declare function detectSchemaVersion(finding: any): string;
export declare function normalizeToCurrentVersion(finding: any): VersionedUnifiedFinding;
export declare function validateSchemaVersion(finding: any, version?: string): {
    valid: boolean;
    errors: string[];
};
export declare function getSchemaVersion(version: string): SchemaVersion | undefined;
export declare function getAvailableVersions(): string[];
export declare function needsMigration(finding: any): boolean;
export declare function migrateFindings(findings: any[], fromVersion?: string): VersionedUnifiedFinding[];
