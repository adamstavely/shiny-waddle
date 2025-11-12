"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PolicyVersioning = void 0;
const fs = require("fs/promises");
const path = require("path");
class PolicyVersioning {
    constructor(versionsDir = './policies/versions') {
        this.versionsDir = versionsDir;
    }
    async createVersion(policies, changeDescription, author, tags) {
        const version = this.generateVersion();
        const timestamp = new Date();
        const versionData = {
            version,
            timestamp,
            policies,
            changeDescription,
            author,
            tags,
        };
        await this.saveVersion(versionData);
        await this.updateCurrentVersion(version);
        return versionData;
    }
    async getVersion(version) {
        try {
            const filePath = path.join(this.versionsDir, `${version}.json`);
            const content = await fs.readFile(filePath, 'utf-8');
            return JSON.parse(content);
        }
        catch (error) {
            return null;
        }
    }
    async getCurrentVersion() {
        try {
            const currentPath = path.join(this.versionsDir, 'current.json');
            const content = await fs.readFile(currentPath, 'utf-8');
            const { version } = JSON.parse(content);
            return this.getVersion(version);
        }
        catch (error) {
            return null;
        }
    }
    async listVersions() {
        try {
            const files = await fs.readdir(this.versionsDir);
            const versionFiles = files.filter(f => f.endsWith('.json') && f !== 'current.json');
            const versions = [];
            for (const file of versionFiles) {
                const version = file.replace('.json', '');
                const versionData = await this.getVersion(version);
                if (versionData) {
                    versions.push(versionData);
                }
            }
            return versions.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
        }
        catch (error) {
            return [];
        }
    }
    async rollback(version) {
        const targetVersion = await this.getVersion(version);
        if (!targetVersion) {
            throw new Error(`Version ${version} not found`);
        }
        const rollbackVersion = await this.createVersion(targetVersion.policies, `Rollback to version ${version}`, 'system');
        return rollbackVersion;
    }
    async diff(version1, version2) {
        const v1 = await this.getVersion(version1);
        const v2 = await this.getVersion(version2);
        if (!v1 || !v2) {
            throw new Error('One or both versions not found');
        }
        const changes = [];
        const v1Policies = new Map(v1.policies.map(p => [p.id, p]));
        const v2Policies = new Map(v2.policies.map(p => [p.id, p]));
        for (const [id, policy] of v2Policies) {
            if (!v1Policies.has(id)) {
                changes.push({
                    type: 'added',
                    policyId: id,
                    newPolicy: policy,
                });
            }
            else {
                const oldPolicy = v1Policies.get(id);
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
    async analyzeChangeImpact(oldVersion, newVersion) {
        const diff = await this.diff(oldVersion, newVersion);
        const breakingChanges = [];
        const warnings = [];
        const affectedResources = new Set();
        for (const change of diff.changes) {
            if (change.type === 'deleted') {
                breakingChanges.push(change);
                warnings.push(`Policy ${change.policyId} was deleted - may break existing access`);
            }
            else if (change.type === 'modified') {
                if (this.isBreakingChange(change.oldPolicy, change.newPolicy)) {
                    breakingChanges.push(change);
                    warnings.push(`Policy ${change.policyId} has breaking changes`);
                }
                if (change.newPolicy) {
                    this.extractResources(change.newPolicy, affectedResources);
                }
            }
            else if (change.type === 'added') {
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
    isBreakingChange(oldPolicy, newPolicy) {
        if (oldPolicy.effect === 'allow' && newPolicy.effect === 'deny') {
            return true;
        }
        if (newPolicy.conditions.length < oldPolicy.conditions.length) {
            return true;
        }
        if (newPolicy.effect === 'deny' &&
            (newPolicy.priority || 0) > (oldPolicy.priority || 0)) {
            return true;
        }
        return false;
    }
    extractResources(policy, resources) {
        for (const condition of policy.conditions) {
            if (condition.attribute.startsWith('resource.')) {
                const resourceType = condition.attribute.split('.')[1];
                resources.add(resourceType);
            }
        }
    }
    policiesEqual(p1, p2) {
        return JSON.stringify(p1) === JSON.stringify(p2);
    }
    generateVersion() {
        const now = new Date();
        const timestamp = now.toISOString().replace(/[:.]/g, '-').slice(0, -5);
        return `v${timestamp}`;
    }
    async saveVersion(version) {
        await fs.mkdir(this.versionsDir, { recursive: true });
        const filePath = path.join(this.versionsDir, `${version.version}.json`);
        await fs.writeFile(filePath, JSON.stringify(version, null, 2));
    }
    async updateCurrentVersion(version) {
        await fs.mkdir(this.versionsDir, { recursive: true });
        const currentPath = path.join(this.versionsDir, 'current.json');
        await fs.writeFile(currentPath, JSON.stringify({ version }, null, 2));
    }
    async getVersionHistory(limit) {
        const versions = await this.listVersions();
        return limit ? versions.slice(0, limit) : versions;
    }
    async tagVersion(version, tags) {
        const versionData = await this.getVersion(version);
        if (!versionData) {
            throw new Error(`Version ${version} not found`);
        }
        versionData.tags = [...(versionData.tags || []), ...tags];
        await this.saveVersion(versionData);
    }
    async getVersionsByTag(tag) {
        const versions = await this.listVersions();
        return versions.filter(v => v.tags?.includes(tag));
    }
}
exports.PolicyVersioning = PolicyVersioning;
//# sourceMappingURL=policy-versioning.js.map