/**
 * Real-Time Finding Ingestion Service
 * 
 * Handles webhook receivers, streaming data processing, real-time normalization, and risk scoring
 */

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
  batchTimeout?: number; // milliseconds
  maxConcurrency?: number;
}

export class RealtimeIngestionService extends EventEmitter {
  private normalizationEngine: NormalizationEngine;
  private riskScorer: EnhancedRiskScorer;
  private config: IngestionConfig;
  private processingQueue: Array<{
    payload: WebhookPayload;
    resolve: (findings: UnifiedFinding[]) => void;
    reject: (error: Error) => void;
  }> = [];
  private isProcessing: boolean = false;
  private batchTimer?: NodeJS.Timeout;

  constructor(
    normalizationEngine: NormalizationEngine,
    riskScorer: EnhancedRiskScorer,
    config: Partial<IngestionConfig> = {}
  ) {
    super();
    this.normalizationEngine = normalizationEngine;
    this.riskScorer = riskScorer;
    this.config = {
      enableRealTimeNormalization: config.enableRealTimeNormalization !== false,
      enableRealTimeRiskScoring: config.enableRealTimeRiskScoring !== false,
      batchSize: config.batchSize || 10,
      batchTimeout: config.batchTimeout || 1000,
      maxConcurrency: config.maxConcurrency || 5,
    };
  }

  /**
   * Process webhook payload from scanner
   */
  async processWebhook(payload: WebhookPayload): Promise<UnifiedFinding[]> {
    return new Promise((resolve, reject) => {
      this.processingQueue.push({ payload, resolve, reject });
      this.emit('finding_received', {
        type: 'finding_received',
        timestamp: new Date(),
        rawPayload: payload,
        metadata: payload.metadata,
      } as IngestionEvent);

      // Start processing if not already running
      if (!this.isProcessing) {
        this.processQueue();
      }
    });
  }

  /**
   * Process queue of webhook payloads
   */
  private async processQueue(): Promise<void> {
    if (this.processingQueue.length === 0) {
      this.isProcessing = false;
      return;
    }

    this.isProcessing = true;

    // Clear any existing batch timer
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }

    // Wait for batch timeout or batch size
    const batch: typeof this.processingQueue = [];
    const startTime = Date.now();

    while (
      batch.length < (this.config.batchSize || 10) &&
      this.processingQueue.length > 0 &&
      Date.now() - startTime < (this.config.batchTimeout || 1000)
    ) {
      batch.push(this.processingQueue.shift()!);
    }

    // Process batch
    try {
      const results = await Promise.allSettled(
        batch.map(item => this.processPayload(item.payload))
      );

      // Resolve/reject promises
      results.forEach((result, index) => {
        const item = batch[index];
        if (result.status === 'fulfilled') {
          item.resolve(result.value);
        } else {
          item.reject(result.reason);
        }
      });
    } catch (error: any) {
      // Reject all items in batch on error
      batch.forEach(item => {
        item.reject(error);
      });
    }

    // Continue processing if queue is not empty
    if (this.processingQueue.length > 0) {
      setImmediate(() => this.processQueue());
    } else {
      this.isProcessing = false;
    }
  }

  /**
   * Process individual payload
   */
  private async processPayload(payload: WebhookPayload): Promise<UnifiedFinding[]> {
    try {
      // Step 1: Normalize findings
      let findings: UnifiedFinding[] = [];

      if (this.config.enableRealTimeNormalization) {
        findings = await this.normalizeFindings(payload);
      } else {
        // Basic normalization without full engine
        findings = payload.findings.map((f, idx) => ({
          id: `finding-${Date.now()}-${idx}`,
          event: {
            kind: 'event',
            category: 'security',
            type: 'vulnerability',
            action: 'detected',
            severity: 500,
          },
          source: this.mapScannerToSource(payload.scannerId),
          scannerId: payload.scannerId as any,
          scannerFindingId: f.id || `finding-${idx}`,
          title: f.title || f.name || 'Security Finding',
          description: f.description || '',
          severity: this.mapSeverity(f.severity || 'medium'),
          confidence: 'confirmed',
          asset: {
            type: 'application',
            applicationId: payload.metadata?.applicationId,
            component: f.component || '',
          },
          status: 'open',
          createdAt: new Date(),
          updatedAt: new Date(),
          riskScore: 50,
          raw: f,
        }));
      }

      // Step 2: Real-time risk scoring
      if (this.config.enableRealTimeRiskScoring) {
        findings = await this.scoreFindings(findings, payload.metadata);
      }

      // Emit normalized event
      findings.forEach(finding => {
        this.emit('finding_normalized', {
          type: 'finding_normalized',
          timestamp: new Date(),
          finding,
          metadata: payload.metadata,
        } as IngestionEvent);
      });

      return findings;
    } catch (error: any) {
      this.emit('error', {
        type: 'error',
        timestamp: new Date(),
        error,
        rawPayload: payload,
      } as IngestionEvent);
      throw error;
    }
  }

  /**
   * Normalize findings using normalization engine
   */
  private async normalizeFindings(payload: WebhookPayload): Promise<UnifiedFinding[]> {
    const normalized: UnifiedFinding[] = [];

    for (const rawFinding of payload.findings) {
      try {
        const result = await this.normalizationEngine.normalize(
          payload.scannerId,
          rawFinding,
          payload.metadata
        );
        if (Array.isArray(result)) {
          normalized.push(...result);
        } else {
          normalized.push(result);
        }
      } catch (error: any) {
        console.error(`Failed to normalize finding from ${payload.scannerId}:`, error);
        // Continue with other findings
      }
    }

    return normalized;
  }

  /**
   * Score findings using risk scorer
   */
  private async scoreFindings(
    findings: UnifiedFinding[],
    metadata?: Record<string, any>
  ): Promise<UnifiedFinding[]> {
    const scored: UnifiedFinding[] = [];

    for (const finding of findings) {
      try {
        const riskScore = await this.riskScorer.calculateRiskScore(finding, {
          applicationId: finding.asset.applicationId || metadata?.applicationId,
          applicationName: metadata?.applicationName,
        });

        finding.riskScore = riskScore.totalScore;
        finding.businessImpact = riskScore.businessImpact;

        // Emit scored event
        this.emit('finding_scored', {
          type: 'finding_scored',
          timestamp: new Date(),
          finding,
          metadata,
        } as IngestionEvent);

        scored.push(finding);
      } catch (error: any) {
        console.error('Failed to score finding:', error);
        // Use default risk score
        scored.push(finding);
      }
    }

    return scored;
  }

  /**
   * Map scanner ID to source type
   */
  private mapScannerToSource(scannerId: string): UnifiedFinding['source'] {
    const sourceMap: Record<string, UnifiedFinding['source']> = {
      'sonarqube': 'sast',
      'snyk': 'sca',
      'snyk-container': 'container',
      'owasp-zap': 'dast',
      'checkov': 'iac',
      'trivy': 'container',
      'clair': 'container',
      'sonatype-iq': 'sca',
      'aws-security-hub': 'cspm',
    };
    return sourceMap[scannerId.toLowerCase()] || 'security';
  }

  /**
   * Map severity string to unified severity
   */
  private mapSeverity(severity: string | number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (typeof severity === 'number') {
      if (severity >= 9) return 'critical';
      if (severity >= 7) return 'high';
      if (severity >= 4) return 'medium';
      if (severity > 0) return 'low';
      return 'info';
    }

    const severityStr = severity.toLowerCase();
    if (severityStr.includes('critical') || severityStr.includes('critical')) return 'critical';
    if (severityStr.includes('high') || severityStr.includes('severe')) return 'high';
    if (severityStr.includes('medium') || severityStr.includes('moderate')) return 'medium';
    if (severityStr.includes('low') || severityStr.includes('negligible')) return 'low';
    return 'info';
  }

  /**
   * Get ingestion statistics
   */
  getStats(): {
    queueLength: number;
    isProcessing: boolean;
    config: IngestionConfig;
  } {
    return {
      queueLength: this.processingQueue.length,
      isProcessing: this.isProcessing,
      config: this.config,
    };
  }

  /**
   * Stop processing and clear queue
   */
  stop(): void {
    this.processingQueue.forEach(item => {
      item.reject(new Error('Ingestion service stopped'));
    });
    this.processingQueue = [];
    this.isProcessing = false;
    if (this.batchTimer) {
      clearTimeout(this.batchTimer);
      this.batchTimer = undefined;
    }
  }
}

