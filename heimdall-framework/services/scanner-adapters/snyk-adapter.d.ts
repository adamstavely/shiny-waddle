import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface SnykVulnerability {
    id: string;
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    package: string;
    version: string;
    packageManager?: string;
    cves?: string[];
    cwe?: string[];
    cvssScore?: number;
    identifiers?: {
        CVE?: string[];
        CWE?: string[];
        GHSA?: string[];
    };
    credit?: string[];
    disclosureTime?: string;
    publicationTime?: string;
    modificationTime?: string;
    language?: string;
    packageName?: string;
    from?: string[];
    upgradePath?: string[];
    isUpgradable?: boolean;
    isPatchable?: boolean;
    isPinnable?: boolean;
    name?: string;
    versionInstalled?: string;
    fixedIn?: string[];
    semver?: {
        vulnerable?: string[];
    };
    dockerfileInstruction?: string;
    dockerBaseImage?: string;
    dockerImageId?: string;
    dockerImageName?: string;
    dockerImageTag?: string;
}
export interface SnykIssue {
    id: string;
    issueType: 'vulnerability' | 'license' | 'configuration';
    pkgName: string;
    pkgVersion?: string;
    language?: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    title: string;
    description: string;
    from?: string[];
    upgradePath?: string[];
    isUpgradable?: boolean;
    isPatchable?: boolean;
    identifiers?: {
        CVE?: string[];
        CWE?: string[];
        GHSA?: string[];
    };
    cvssScore?: number;
    cves?: string[];
    cwe?: string[];
    dockerfileInstruction?: string;
    dockerBaseImage?: string;
}
export declare class SnykAdapter extends BaseScannerAdapter {
    private scanType;
    constructor(config: any, scanType?: 'sca' | 'container');
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractCVE;
    private extractCWE;
    private extractRemediationDescription;
    private extractRemediationSteps;
    private extractReferences;
    private mapSeverityToECS;
}
