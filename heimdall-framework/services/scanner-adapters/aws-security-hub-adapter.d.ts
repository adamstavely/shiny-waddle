import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface AWSSecurityHubFinding {
    Id: string;
    ProductArn: string;
    ProductName?: string;
    AwsAccountId: string;
    Region: string;
    GeneratorId: string;
    CreatedAt: string;
    UpdatedAt: string;
    SchemaVersion: string;
    Title: string;
    Description: string;
    Severity: {
        Label: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
        Normalized: number;
        Product?: number;
        Original?: string;
    };
    Compliance?: {
        Status: 'PASSED' | 'WARNING' | 'FAILED' | 'NOT_AVAILABLE';
        RelatedRequirements?: string[];
        StatusReasons?: Array<{
            ReasonCode: string;
            Description: string;
        }>;
    };
    ProductFields?: Record<string, string>;
    Resources: Array<{
        Type: string;
        Id: string;
        Partition?: string;
        Region?: string;
        Tags?: Record<string, string>;
        Details?: Record<string, any>;
    }>;
    Remediation?: {
        Recommendation?: {
            Text: string;
            Url?: string;
        };
    };
    Workflow?: {
        Status: 'NEW' | 'NOTIFIED' | 'RESOLVED' | 'SUPPRESSED';
    };
    RecordState?: 'ACTIVE' | 'ARCHIVED';
    RelatedFindings?: Array<{
        ProductArn: string;
        Id: string;
    }>;
}
export declare class AWSSecurityHubAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractFrameworks;
    private extractRemediationSteps;
    private mapStatus;
    private mapSeverityToECS;
}
