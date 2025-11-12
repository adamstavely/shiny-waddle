import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface SonarQubeIssue {
    key: string;
    rule: string;
    severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
    component: string;
    project: string;
    line?: number;
    message: string;
    type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';
    flows?: Array<{
        locations: Array<{
            component: string;
            textRange: {
                startLine: number;
                endLine: number;
                startOffset: number;
                endOffset: number;
            };
        }>;
    }>;
    textRange?: {
        startLine: number;
        endLine: number;
        startOffset: number;
        endOffset: number;
    };
    status?: string;
    resolution?: string;
    ruleDescription?: string;
    remediation?: {
        func?: string;
        message?: string;
    };
}
export declare class SonarQubeAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractFilePath;
    private mapStatus;
    private mapSeverityToECS;
}
