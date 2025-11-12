import { UnifiedFinding } from '../core/unified-finding-schema';
import { BaseScannerAdapter } from './scanner-adapters/base-adapter';
export interface NormalizationConfig {
    deduplication: {
        enabled: boolean;
        strategy: 'exact' | 'fuzzy' | 'semantic';
        similarityThreshold?: number;
    };
    enrichment: {
        enabled: boolean;
        enrichCVE?: boolean;
        enrichCWE?: boolean;
        enrichCompliance?: boolean;
    };
    validation: {
        enabled: boolean;
        strictMode?: boolean;
    };
}
export interface ScannerResult {
    scannerId: string;
    source: string;
    findings: any[];
    metadata?: Record<string, any>;
}
export declare class NormalizationEngine {
    private adapters;
    private ecsAdapter;
    private config;
    constructor(config?: Partial<NormalizationConfig>);
    private initializeAdapters;
    registerAdapter(scannerId: string, adapter: BaseScannerAdapter): void;
    normalize(scannerResults: ScannerResult[]): Promise<UnifiedFinding[]>;
    normalizeSingle(scannerId: string, findings: any[], metadata?: Record<string, any>): Promise<UnifiedFinding[]>;
    toECS(findings: UnifiedFinding[]): any[];
    fromECS(docs: any[]): UnifiedFinding[];
    private enrichFindings;
    private enrichComplianceMapping;
    private validateFindings;
    private deduplicateFindings;
    private exactDeduplication;
    private fuzzyDeduplication;
    private generateDeduplicationKey;
    private calculateSimilarity;
    private stringSimilarity;
    private isMoreSevere;
}
