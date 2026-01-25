import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';
export interface CheckovCheck {
    check_id: string;
    bc_check_id?: string;
    check_name: string;
    check_result: {
        result: 'PASSED' | 'FAILED' | 'SKIPPED';
        evaluated_keys: string[];
    };
    code_block?: Array<[number, string]>;
    file_path: string;
    file_line_range: [number, number];
    resource: string;
    guideline?: string;
    severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    description?: string;
    short_description?: string;
    vulnerability_details?: {
        id?: string;
        cve_id?: string;
        cwe_id?: string;
        description?: string;
    };
    fixed_definition?: string;
    entity_tags?: Record<string, string>;
}
export declare class CheckovAdapter extends BaseScannerAdapter {
    constructor(config: any);
    validate(finding: ScannerFinding): boolean;
    normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding;
    protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    private extractFilePath;
    private extractFrameworks;
    private extractRemediationSteps;
    private extractReferences;
    private mapSeverityToECS;
}
