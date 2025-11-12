import { UnifiedFinding } from '../core/unified-finding-schema';
import { NormalizationEngine } from './normalization-engine';
import { EnhancedRiskScorer } from './enhanced-risk-scorer';
import { EventEmitter } from 'events';
export interface WebhookPayload {
    scannerId: string;
    scannerName?: string;
    timestamp?: string;
    findings: any[];
    metadata?: {
        applicationId?: string;
        applicationName?: string;
        scanId?: string;
        scanType?: string;
        [key: string]: any;
    };
}
export interface IngestionEvent {
    type: 'finding_received' | 'finding_normalized' | 'finding_scored' | 'error';
    timestamp: Date;
    finding?: UnifiedFinding;
    rawPayload?: any;
    error?: Error;
    metadata?: Record<string, any>;
}
export interface IngestionConfig {
    enableRealTimeNormalization: boolean;
    enableRealTimeRiskScoring: boolean;
    batchSize?: number;
    batchTimeout?: number;
    maxConcurrency?: number;
}
export declare class RealtimeIngestionService extends EventEmitter {
    private normalizationEngine;
    private riskScorer;
    private config;
    private processingQueue;
    private isProcessing;
    private batchTimer?;
    constructor(normalizationEngine: NormalizationEngine, riskScorer: EnhancedRiskScorer, config?: Partial<IngestionConfig>);
    processWebhook(payload: WebhookPayload): Promise<UnifiedFinding[]>;
    private processQueue;
    private processPayload;
    private normalizeFindings;
    private scoreFindings;
    private mapScannerToSource;
    private mapSeverity;
    getStats(): {
        queueLength: number;
        isProcessing: boolean;
        config: IngestionConfig;
    };
    stop(): void;
}
