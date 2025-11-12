"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.registerAllMigrations = registerAllMigrations;
const schema_versioning_1 = require("./schema-versioning");
function migrate_0_9_0_to_1_0_0(finding) {
    const migrated = {
        ...finding,
    };
    if (!migrated.event) {
        migrated.event = {
            kind: 'event',
            category: 'security',
            type: 'vulnerability',
            action: 'detected',
            severity: 0,
        };
    }
    if (migrated.severity && !migrated.event.severity) {
        const severityMap = {
            'critical': 900,
            'high': 700,
            'medium': 500,
            'low': 300,
            'info': 100,
        };
        migrated.event.severity = severityMap[migrated.severity] || 500;
    }
    if (!migrated.asset) {
        migrated.asset = {
            type: 'application',
        };
    }
    else if (typeof migrated.asset === 'string') {
        migrated.asset = {
            type: migrated.asset,
        };
    }
    if (!migrated.remediation) {
        migrated.remediation = {
            description: migrated.description || 'No remediation provided',
            steps: [],
            references: [],
        };
    }
    else if (typeof migrated.remediation === 'string') {
        migrated.remediation = {
            description: migrated.remediation,
            steps: [],
            references: [],
        };
    }
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
    if (typeof migrated.riskScore !== 'number') {
        const severityScores = {
            'critical': 90,
            'high': 70,
            'medium': 50,
            'low': 30,
            'info': 10,
        };
        migrated.riskScore = severityScores[migrated.severity] || 50;
    }
    if (!migrated.status) {
        migrated.status = 'open';
    }
    if (!migrated.confidence) {
        migrated.confidence = 'tentative';
    }
    return migrated;
}
function registerAllMigrations() {
    (0, schema_versioning_1.registerMigration)('0.9.0', '1.0.0', migrate_0_9_0_to_1_0_0);
}
registerAllMigrations();
//# sourceMappingURL=schema-migrations.js.map