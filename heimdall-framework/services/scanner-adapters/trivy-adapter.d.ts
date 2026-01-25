import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface TrivyResult {
    Target: string;
    Type: string;
    Vulnerabilities?: TrivyVulnerability[];
    Misconfigurations?: TrivyMisconfiguration[];
}
export interface TrivyVulnerability {
    VulnerabilityID: string;
    PkgName: string;
    PkgPath?: string;
    InstalledVersion: string;
    FixedVersion?: string;
    Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    Title: string;
    Description: string;
    PrimaryURL?: string;
    PublishedDate?: string;
    LastModifiedDate?: string;
    CweIDs?: string[];
    CVSS?: {
        nvd?: {
            V3Score?: number;
            V3Vector?: string;
        };
        redhat?: {
            V3Score?: number;
            V3Vector?: string;
        };
    };
    References?: string[];
}
export interface TrivyMisconfiguration {
    Type: string;
    ID: string;
    AVOIDance: string;
    Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
    Title: string;
    Description: string;
    Message?: string;
    Resolution?: string;
    Status?: string;
    Layer?: {
        DiffID?: string;
    };
    IacMetadata?: {
        Resource?: string;
        Provider?: string;
        Service?: string;
        StartLine?: number;
        EndLine?: number;
    };
}
export declare class TrivyAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding[];
    private normalizeVulnerability;
    private normalizeMisconfiguration;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private parseImageName;
    private mapSeverityToECS;
}
