import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface SonatypeIQComponent {
    packageUrl?: string;
    hash?: string;
    componentIdentifier?: {
        format: string;
        coordinates: {
            groupId?: string;
            artifactId?: string;
            version?: string;
            extension?: string;
        };
    };
    displayName?: string;
}
export interface SonatypeIQVulnerability {
    id: string;
    source?: string;
    cve?: string;
    cwe?: string;
    cvssScore?: number;
    cvssVector?: string;
    severity?: 'CRITICAL' | 'SEVERE' | 'MODERATE' | 'LOW' | 'INFO';
    title?: string;
    description?: string;
    reference?: string;
    publishedDate?: string;
    disclosedDate?: string;
    remediation?: {
        version?: string;
        description?: string;
    };
}
export interface SonatypeIQPolicyViolation {
    policyId: string;
    policyName: string;
    threatLevel: number;
    policyViolationId: string;
    constraintId: string;
    constraintName: string;
    stageId: string;
    reportTime?: string;
}
export interface SonatypeIQLicense {
    licenseId: string;
    licenseName: string;
    licenseText?: string;
    licenseThreatGroup?: number;
}
export interface SonatypeIQFinding {
    component: SonatypeIQComponent;
    vulnerabilities?: SonatypeIQVulnerability[];
    policyViolations?: SonatypeIQPolicyViolation[];
    licenses?: SonatypeIQLicense[];
    matchState?: string;
    pathnames?: string[];
    proprietary?: boolean;
    applicationId?: string;
    applicationName?: string;
    stage?: string;
    scanId?: string;
    scanTime?: string;
}
export interface SonatypeIQReport {
    reportDataUrl?: string;
    isError?: boolean;
    errorMessage?: string;
    application?: {
        id: string;
        publicId: string;
        name: string;
    };
    components?: SonatypeIQFinding[];
    summary?: {
        totalComponentCount?: number;
        vulnerableComponentCount?: number;
        criticalComponentCount?: number;
        severeComponentCount?: number;
        moderateComponentCount?: number;
        lowComponentCount?: number;
    };
}
export declare class SonatypeIQAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding | UnifiedFinding[];
    private normalizeComponent;
    private normalizeVulnerability;
    private normalizePolicyViolation;
    private normalizeLicenseIssue;
    private normalizeComponentOnly;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractComponentName;
    private extractComponentVersion;
    private mapThreatLevelToSeverity;
    private mapLicenseThreatToSeverity;
    private extractRemediationDescription;
    private extractRemediationSteps;
    private extractReferences;
    private mapSeverityToECS;
}
