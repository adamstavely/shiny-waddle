import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { RealtimeIngestionService, WebhookPayload, IngestionEvent } from '../../../heimdall-framework/services/realtime-ingestion';
import { NormalizationEngine } from '../../../heimdall-framework/services/normalization-engine';
import { EnhancedRiskScorer } from '../../../heimdall-framework/services/enhanced-risk-scorer';
import { DashboardSSEGateway, DashboardUpdate } from '../dashboard/dashboard-sse.gateway';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { UnifiedFinding } from '../../../heimdall-framework/core/unified-finding-schema';
import { ElasticsearchService } from '../elasticsearch/elasticsearch.service';

@Injectable()
export class RealtimeService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RealtimeService.name);
  private ingestionService: RealtimeIngestionService;
  private isRunning = false;

  constructor(
    private readonly sseGateway: DashboardSSEGateway,
    private readonly unifiedFindingsService: UnifiedFindingsService,
    private readonly elasticsearchService: ElasticsearchService,
  ) {
    // Initialize normalization engine and risk scorer
    const normalizationEngine = new NormalizationEngine({
      deduplication: {
        enabled: true,
        strategy: 'fuzzy',
        similarityThreshold: 0.8,
      },
      enrichment: {
        enabled: true,
        enrichCVE: true,
        enrichCWE: true,
        enrichCompliance: true,
      },
      validation: {
        enabled: true,
        strictMode: false,
      },
    });

    const riskScorer = new EnhancedRiskScorer();

    // Initialize ingestion service
    this.ingestionService = new RealtimeIngestionService(
      normalizationEngine,
      riskScorer,
      {
        enableRealTimeNormalization: true,
        enableRealTimeRiskScoring: true,
        batchSize: 10,
        batchTimeout: 1000,
        maxConcurrency: 5,
      }
    );

    // Set up event listeners
    this.setupEventListeners();
  }

  onModuleInit() {
    this.logger.log('RealtimeService initialized');
    this.start();
  }

  onModuleDestroy() {
    this.logger.log('Stopping RealtimeService');
    this.stop();
  }

  /**
   * Set up event listeners for ingestion service events
   */
  private setupEventListeners(): void {
    this.ingestionService.on('finding_received', (event: IngestionEvent) => {
      this.logger.debug(`Finding received: ${event.rawPayload?.scannerId}`);
    });

    this.ingestionService.on('finding_normalized', async (event: IngestionEvent) => {
      if (event.finding) {
        this.logger.debug(`Finding normalized: ${event.finding.id}`);
        
        // Store finding in unified findings service
        try {
          await this.unifiedFindingsService.createFinding(event.finding);
        } catch (error) {
          this.logger.error(`Failed to store finding ${event.finding.id}:`, error);
        }

        // Send to Elasticsearch for dashboarding and reporting
        try {
          await this.elasticsearchService.indexFinding(event.finding);
        } catch (error) {
          this.logger.error(`Failed to index finding ${event.finding.id} to Elasticsearch:`, error);
          // Don't throw - Elasticsearch failures shouldn't break ingestion
        }

        // Broadcast update via SSE
        this.broadcastFindingUpdate(event.finding, 'finding_normalized');
      }
    });

    this.ingestionService.on('finding_scored', async (event: IngestionEvent) => {
      if (event.finding) {
        this.logger.debug(`Finding scored: ${event.finding.id}, score: ${event.finding.riskScore}`);
        
        // Update in Elasticsearch (re-index with updated risk score)
        try {
          await this.elasticsearchService.indexFinding(event.finding);
        } catch (error) {
          this.logger.error(`Failed to update finding ${event.finding.id} in Elasticsearch:`, error);
          // Don't throw - Elasticsearch failures shouldn't break ingestion
        }

        // Send event to Elasticsearch
        try {
          await this.elasticsearchService.indexEvent('finding_scored', {
            findingId: event.finding.id,
            riskScore: event.finding.riskScore,
            severity: event.finding.severity,
          }, {
            'heimdall.finding.id': event.finding.id,
            'heimdall.risk_score': event.finding.riskScore,
          });
        } catch (error) {
          this.logger.error(`Failed to index scoring event for ${event.finding.id}:`, error);
        }
        
        // Broadcast update via SSE
        this.broadcastFindingUpdate(event.finding, 'finding_scored');
      }
    });

    this.ingestionService.on('error', async (event: IngestionEvent) => {
      this.logger.error(`Ingestion error:`, event.error);
      
      // Send error event to Elasticsearch
      try {
        await this.elasticsearchService.indexEvent('ingestion_error', {
          message: 'Real-time ingestion error',
          error: event.error?.message,
          severity: 'high',
        }, {
          'error.message': event.error?.message,
          'error.type': event.error?.name,
        });
      } catch (error) {
        this.logger.error('Failed to index error event to Elasticsearch:', error);
      }
      
      // Broadcast error update
      this.sseGateway.broadcast({
        type: 'notification',
        data: {
          type: 'error',
          message: 'Real-time ingestion error',
          error: event.error?.message,
          timestamp: event.timestamp,
        },
        timestamp: event.timestamp,
      });
    });
  }

  /**
   * Broadcast finding update via SSE
   */
  private broadcastFindingUpdate(finding: UnifiedFinding, eventType: string): void {
    const update: DashboardUpdate = {
      type: 'violation', // Using 'violation' type for findings
      data: {
        finding,
        eventType,
        applicationId: finding.asset?.applicationId,
        timestamp: finding.updatedAt || finding.createdAt,
      },
      timestamp: finding.updatedAt || finding.createdAt || new Date(),
    };

    this.sseGateway.broadcast(update);
  }

  /**
   * Process webhook payload
   */
  async processWebhook(payload: WebhookPayload): Promise<UnifiedFinding[]> {
    if (!this.isRunning) {
      throw new Error('Realtime ingestion service is not running');
    }

    try {
      const findings = await this.ingestionService.processWebhook(payload);
      this.logger.log(`Processed webhook from ${payload.scannerId}, received ${findings.length} findings`);
      return findings;
    } catch (error) {
      this.logger.error(`Failed to process webhook:`, error);
      throw error;
    }
  }

  /**
   * Start ingestion service
   */
  start(): void {
    if (this.isRunning) {
      this.logger.warn('Ingestion service is already running');
      return;
    }

    this.isRunning = true;
    this.logger.log('Real-time ingestion service started');
  }

  /**
   * Stop ingestion service
   */
  stop(): void {
    if (!this.isRunning) {
      this.logger.warn('Ingestion service is not running');
      return;
    }

    this.ingestionService.stop();
    this.isRunning = false;
    this.logger.log('Real-time ingestion service stopped');
  }

  /**
   * Get ingestion statistics
   */
  getStats() {
    const stats = this.ingestionService.getStats();
    return {
      ...stats,
      isRunning: this.isRunning,
      connectedClients: this.sseGateway.getClientCount(),
    };
  }

  /**
   * Check if service is running
   */
  isServiceRunning(): boolean {
    return this.isRunning;
  }
}
