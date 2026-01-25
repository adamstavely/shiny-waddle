import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface OWASPZAPAlert {
    id: number;
    name: string;
    description: string;
    solution: string;
    reference: string;
    cweid?: number;
    wascid?: number;
    sourceid?: number;
    pluginId: string;
    alert: string;
    risk: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
    confidence: 'False Positive' | 'Low' | 'Medium' | 'High' | 'Confirmed';
    message?: {
        requestHeader?: string;
        requestBody?: string;
        responseHeader?: string;
        responseBody?: string;
    };
    url: string;
    method?: string;
    param?: string;
    attack?: string;
    evidence?: string;
    other?: string;
    otherInfo?: string;
    instances?: Array<{
        url: string;
        method: string;
        param?: string;
        attack?: string;
        evidence?: string;
    }>;
}
export declare class OWASPZAPAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private mapConfidence;
    private mapExploitability;
    private parseURL;
    private extractRemediationSteps;
    private extractReferences;
    private mapSeverityToECS;
}
