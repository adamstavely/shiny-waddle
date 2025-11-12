import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface GCPSecurityCommandCenterFinding {
    name: string;
    parent: string;
    resourceName: string;
    state: 'ACTIVE' | 'INACTIVE';
    category: string;
    externalUri?: string;
    sourceProperties: {
        ScannerName?: string;
        FindingClass?: string;
        State?: string;
        Severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
        FindingProviderId?: string;
        FindingProviderName?: string;
        FindingId?: string;
        FindingSource?: string;
        FindingSourceId?: string;
        FindingSourceUrl?: string;
        FindingSourceUpdateTime?: string;
        FindingSourceCreateTime?: string;
        FindingSourceSeverity?: string;
        FindingSourceCategory?: string;
        FindingSourceDescription?: string;
        FindingSourceRecommendation?: string;
        FindingSourceRemediation?: string;
        FindingSourceCompliance?: string[];
        FindingSourceCVE?: string;
        FindingSourceCWE?: string;
        FindingSourceCVSS?: number;
        FindingSourceExploitability?: string;
        FindingSourceConfidence?: number;
        FindingSourceAssetType?: string;
        FindingSourceAssetId?: string;
        FindingSourceAssetName?: string;
        FindingSourceAssetLocation?: string;
        FindingSourceAssetProject?: string;
        FindingSourceAssetZone?: string;
        FindingSourceAssetRegion?: string;
        FindingSourceAssetLabels?: Record<string, string>;
        FindingSourceAssetTags?: string[];
        FindingSourceAssetMetadata?: Record<string, any>;
        [key: string]: any;
    };
    securityMarks?: {
        marks?: Record<string, string>;
    };
    eventTime?: string;
    createTime?: string;
    updateTime?: string;
}
export declare class GCPSecurityCommandCenterAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractCompliance;
    private extractRemediationSteps;
    private mapStatus;
    private mapExploitability;
    private mapSeverityToECS;
}
