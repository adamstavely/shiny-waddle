import { UnifiedFinding, ScannerSource, ScannerId } from '../../core/unified-finding-schema';
export interface ScannerFinding {
    [key: string]: any;
}
export interface AdapterConfig {
    scannerId: ScannerId;
    source: ScannerSource;
    enabled: boolean;
    config?: Record<string, any>;
}
export declare abstract class BaseScannerAdapter {
    protected config: AdapterConfig;
    constructor(config: AdapterConfig);
    abstract normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding | UnifiedFinding[];
    abstract validate(finding: ScannerFinding): boolean;
    protected abstract extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';
    protected extractVulnerabilityInfo(finding: ScannerFinding): {
        cveId?: string;
        cweId?: string;
        cvssScore?: number;
        cvssVector?: string;
    };
    protected extractFileLocation(finding: ScannerFinding): {
        file?: string;
        line?: number;
        column?: number;
    };
    protected extractRemediation(finding: ScannerFinding): {
        description: string;
        steps: string[];
        references: string[];
    };
    protected generateFindingId(scannerFindingId: string): string;
    protected calculateRiskScore(severity: string, exploitability?: string, assetCriticality?: string): number;
    batchNormalize(findings: ScannerFinding[], metadata?: Record<string, any>): UnifiedFinding[];
}
