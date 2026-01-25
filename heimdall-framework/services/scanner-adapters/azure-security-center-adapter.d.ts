import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface AzureSecurityCenterFinding {
    id: string;
    name: string;
    type: string;
    properties: {
        displayName: string;
        description: string;
        remediationDescription?: string;
        severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
        state: 'Active' | 'Resolved' | 'Dismissed';
        timeGeneratedUtc: string;
        vendorName: string;
        alertType: string;
        intent?: string;
        resourceIdentifiers?: {
            azureResourceId?: string;
            workspaceId?: string;
            workspaceSubscriptionId?: string;
            workspaceResourceGroup?: string;
        };
        remediationSteps?: string[];
        extendedProperties?: Record<string, any>;
        compromisedEntity?: string;
        confidenceScore?: number;
        confidenceReasons?: Array<{
            type: string;
            reason: string;
        }>;
        sourceSystemIds?: string[];
        canBeInvestigated?: boolean;
        isIncident?: boolean;
        entities?: Array<{
            type: string;
            id: string;
            name?: string;
        }>;
        extendedLinks?: Array<{
            type: string;
            label: string;
            url: string;
        }>;
    };
    resourceGroup?: string;
    subscriptionId?: string;
}
export declare class AzureSecurityCenterAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractRegion;
    private extractCompliance;
    private extractRemediationSteps;
    private mapStatus;
    private mapSeverityToECS;
}
