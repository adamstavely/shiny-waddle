import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface ClairVulnerability {
    id: string;
    name: string;
    description?: string;
    link?: string;
    severity: 'Unknown' | 'Negligible' | 'Low' | 'Medium' | 'High' | 'Critical';
    package: string;
    version?: string;
    fixedIn?: string;
    namespace?: string;
    feature?: {
        name: string;
        version?: string;
        versionFormat?: string;
        namespace?: string;
    };
}
export interface ClairLayer {
    hash: string;
    parentHash?: string;
    format?: string;
    index?: number;
    features?: ClairFeature[];
}
export interface ClairFeature {
    name: string;
    version?: string;
    versionFormat?: string;
    namespace?: string;
    vulnerabilities?: ClairVulnerability[];
    addedBy?: string;
}
export interface ClairVulnerabilityReport {
    image: string;
    unpatched?: ClairVulnerability[];
    layers?: ClairLayer[];
    vulnerabilities?: ClairVulnerability[];
    summary?: {
        total?: number;
        critical?: number;
        high?: number;
        medium?: number;
        low?: number;
        negligible?: number;
        unknown?: number;
    };
}
export interface ClairAPIResponse {
    image: string;
    vulnerabilities?: ClairVulnerability[];
    layers?: ClairLayer[];
}
export declare class ClairAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding[];
    private normalizeVulnerability;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private isCVE;
    private extractCVSSScore;
    private parseImageName;
    private extractRemediationDescription;
    private extractRemediationSteps;
    private extractReferences;
    private mapSeverityToECS;
}
