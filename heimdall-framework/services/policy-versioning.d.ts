import { ABACPolicy } from '../core/types';
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
export declare class PolicyVersioning {
    private versionsDir;
    constructor(versionsDir?: string);
    createVersion(policies: ABACPolicy[], changeDescription?: string, author?: string, tags?: string[]): Promise<PolicyVersion>;
    getVersion(version: string): Promise<PolicyVersion | null>;
    getCurrentVersion(): Promise<PolicyVersion | null>;
    listVersions(): Promise<PolicyVersion[]>;
    rollback(version: string): Promise<PolicyVersion>;
    diff(version1: string, version2: string): Promise<PolicyDiff>;
    analyzeChangeImpact(oldVersion: string, newVersion: string): Promise<{
        breakingChanges: PolicyChange[];
        warnings: string[];
        affectedResources: string[];
    }>;
    private isBreakingChange;
    private extractResources;
    private policiesEqual;
    private generateVersion;
    private saveVersion;
    private updateCurrentVersion;
    getVersionHistory(limit?: number): Promise<PolicyVersion[]>;
    tagVersion(version: string, tags: string[]): Promise<void>;
    getVersionsByTag(tag: string): Promise<PolicyVersion[]>;
}
