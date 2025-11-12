"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SCHEMA_VERSIONS = exports.CURRENT_SCHEMA_VERSION = void 0;
exports.registerMigration = registerMigration;
exports.migrateFinding = migrateFinding;
exports.detectSchemaVersion = detectSchemaVersion;
exports.normalizeToCurrentVersion = normalizeToCurrentVersion;
exports.validateSchemaVersion = validateSchemaVersion;
exports.getSchemaVersion = getSchemaVersion;
exports.getAvailableVersions = getAvailableVersions;
exports.needsMigration = needsMigration;
exports.migrateFindings = migrateFindings;
exports.CURRENT_SCHEMA_VERSION = '1.0.0';
exports.SCHEMA_VERSIONS = [
    {
        version: '1.0.0',
        releasedAt: new Date('2024-01-01'),
        description: 'Initial unified finding schema with ECS compatibility',
        breakingChanges: [],
    },
];
const MIGRATIONS = new Map();
function registerMigration(fromVersion, toVersion, migration) {
    if (!MIGRATIONS.has(fromVersion)) {
        MIGRATIONS.set(fromVersion, new Map());
    }
    MIGRATIONS.get(fromVersion).set(toVersion, migration);
}
function getMigrationPath(fromVersion, toVersion) {
    const versions = exports.SCHEMA_VERSIONS.map(v => v.version).sort();
    const fromIndex = versions.indexOf(fromVersion);
    const toIndex = versions.indexOf(toVersion);
    if (fromIndex === -1 || toIndex === -1) {
        throw new Error(`Invalid schema version: ${fromVersion} or ${toVersion}`);
    }
    if (fromIndex === toIndex) {
        return [];
    }
    if (fromIndex < toIndex) {
        return versions.slice(fromIndex + 1, toIndex + 1);
    }
    else {
        return versions.slice(toIndex, fromIndex).reverse();
    }
}
function migrateFinding(finding, fromVersion, toVersion = exports.CURRENT_SCHEMA_VERSION) {
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
            }
            else {
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
function detectSchemaVersion(finding) {
    if (finding._schema?.version) {
        return finding._schema.version;
    }
    if (finding.event && finding.asset && finding.remediation) {
        return '1.0.0';
    }
    if (finding.vulnerability && !finding.event) {
        return '0.9.0';
    }
    return exports.CURRENT_SCHEMA_VERSION;
}
function normalizeToCurrentVersion(finding) {
    const detectedVersion = detectSchemaVersion(finding);
    return migrateFinding(finding, detectedVersion, exports.CURRENT_SCHEMA_VERSION);
}
function validateSchemaVersion(finding, version = exports.CURRENT_SCHEMA_VERSION) {
    const errors = [];
    if (version === '1.0.0') {
        if (!finding.id) {
            errors.push('Missing required field: id');
        }
        if (!finding.event) {
            errors.push('Missing required field: event');
        }
        else {
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
        }
        else {
            if (!finding.asset.type) {
                errors.push('Missing required field: asset.type');
            }
        }
        if (!finding.remediation) {
            errors.push('Missing required field: remediation');
        }
        else {
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
function getSchemaVersion(version) {
    return exports.SCHEMA_VERSIONS.find(v => v.version === version);
}
function getAvailableVersions() {
    return exports.SCHEMA_VERSIONS.map(v => v.version);
}
function needsMigration(finding) {
    const detectedVersion = detectSchemaVersion(finding);
    return detectedVersion !== exports.CURRENT_SCHEMA_VERSION;
}
function migrateFindings(findings, fromVersion) {
    return findings.map(finding => {
        if (fromVersion) {
            return migrateFinding(finding, fromVersion);
        }
        return normalizeToCurrentVersion(finding);
    });
}
//# sourceMappingURL=schema-versioning.js.map