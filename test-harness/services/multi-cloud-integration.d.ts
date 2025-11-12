import { UnifiedFinding } from '../core/unified-finding-schema';
export interface CloudProviderConfig {
    provider: 'aws' | 'azure' | 'gcp';
    enabled: boolean;
    config: Record<string, any>;
    regions?: string[];
    resourceTypes?: string[];
}
export interface MultiCloudFinding {
    finding: UnifiedFinding;
    provider: 'aws' | 'azure' | 'gcp';
    region: string;
    resourceId: string;
    accountId?: string;
    subscriptionId?: string;
    projectId?: string;
}
export interface CloudProviderSummary {
    provider: 'aws' | 'azure' | 'gcp';
    totalFindings: number;
    findingsBySeverity: Record<string, number>;
    findingsByRegion: Record<string, number>;
    riskScore: number;
    lastScanTime?: Date;
}
export declare class MultiCloudIntegration {
    private adapters;
    private configs;
    registerProvider(config: CloudProviderConfig): void;
    normalizeProviderFindings(provider: 'aws' | 'azure' | 'gcp', rawFindings: any[]): Promise<UnifiedFinding[]>;
    aggregateFindings(providerFindings: Map<'aws' | 'azure' | 'gcp', any[]>): Promise<MultiCloudFinding[]>;
    getProviderSummaries(findings: MultiCloudFinding[]): Promise<Map<string, CloudProviderSummary>>;
    findCrossCloudDuplicates(findings: MultiCloudFinding[]): Map<string, MultiCloudFinding[]>;
    getFindingsByProvider(findings: MultiCloudFinding[]): Map<string, MultiCloudFinding[]>;
    getFindingsByRegion(findings: MultiCloudFinding[]): Map<string, MultiCloudFinding[]>;
    private extractRegion;
    private extractAccountId;
    private extractSubscriptionId;
    private extractProjectId;
    private generateDuplicateKey;
}
