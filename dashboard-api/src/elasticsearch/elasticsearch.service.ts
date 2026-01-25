import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ECSAdapter } from '../../../heimdall-framework/services/ecs-adapter';
import { UnifiedFinding, ECSDocument } from '../../../heimdall-framework/core/unified-finding-schema';

// Dynamic import for @elastic/elasticsearch to handle optional dependency
let Client: any;
let esClient: any = null;

try {
  // Try to import @elastic/elasticsearch
  Client = require('@elastic/elasticsearch').Client;
} catch (error) {
  // If not installed, Client will be null and we'll handle gracefully
}

export interface ElasticsearchConfig {
  enabled: boolean;
  node?: string | string[];
  cloud?: {
    id: string;
  };
  auth?: {
    username?: string;
    password?: string;
    apiKey?: string;
  };
  indexPrefix?: string;
  maxRetries?: number;
  requestTimeout?: number;
}

@Injectable()
export class ElasticsearchService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ElasticsearchService.name);
  private readonly ecsAdapter: ECSAdapter;
  private client: any = null;
  private config: ElasticsearchConfig;
  private isEnabled = false;

  constructor() {
    this.ecsAdapter = new ECSAdapter();
    this.config = this.loadConfig();
    this.isEnabled = this.config.enabled && Client !== null;
  }

  onModuleInit() {
    if (this.isEnabled) {
      this.initializeClient();
    } else if (this.config.enabled && Client === null) {
      this.logger.warn(
        '@elastic/elasticsearch package not installed. Install it with: npm install @elastic/elasticsearch'
      );
    }
  }

  onModuleDestroy() {
    if (this.client) {
      this.client.close().catch((err: any) => {
        this.logger.error('Error closing Elasticsearch client:', err);
      });
    }
  }

  /**
   * Load configuration from environment variables
   */
  private loadConfig(): ElasticsearchConfig {
    return {
      enabled: process.env.ELASTICSEARCH_ENABLED === 'true',
      node: process.env.ELASTICSEARCH_NODE
        ? process.env.ELASTICSEARCH_NODE.split(',')
        : ['http://localhost:9200'],
      cloud: process.env.ELASTICSEARCH_CLOUD_ID
        ? { id: process.env.ELASTICSEARCH_CLOUD_ID }
        : undefined,
      auth: process.env.ELASTICSEARCH_USERNAME || process.env.ELASTICSEARCH_API_KEY
        ? {
            username: process.env.ELASTICSEARCH_USERNAME,
            password: process.env.ELASTICSEARCH_PASSWORD,
            apiKey: process.env.ELASTICSEARCH_API_KEY,
          }
        : undefined,
      indexPrefix: process.env.ELASTICSEARCH_INDEX_PREFIX || 'heimdall-realtime',
      maxRetries: parseInt(process.env.ELASTICSEARCH_MAX_RETRIES || '3', 10),
      requestTimeout: parseInt(process.env.ELASTICSEARCH_REQUEST_TIMEOUT || '30000', 10),
    };
  }

  /**
   * Initialize Elasticsearch client
   */
  private initializeClient(): void {
    if (!Client) {
      this.logger.warn('Elasticsearch client not available');
      return;
    }

    try {
      const clientConfig: any = {
        maxRetries: this.config.maxRetries,
        requestTimeout: this.config.requestTimeout,
      };

      if (this.config.cloud?.id) {
        clientConfig.cloud = this.config.cloud;
      } else {
        clientConfig.node = this.config.node;
      }

      if (this.config.auth) {
        if (this.config.auth.apiKey) {
          clientConfig.auth = {
            apiKey: this.config.auth.apiKey,
          };
        } else if (this.config.auth.username) {
          clientConfig.auth = {
            username: this.config.auth.username,
            password: this.config.auth.password,
          };
        }
      }

      this.client = new Client(clientConfig);
      this.logger.log('Elasticsearch client initialized');
    } catch (error: any) {
      this.logger.error('Failed to initialize Elasticsearch client:', error);
      this.isEnabled = false;
    }
  }

  /**
   * Check if Elasticsearch is enabled and client is available
   */
  isAvailable(): boolean {
    return this.isEnabled && this.client !== null;
  }

  /**
   * Send a finding to Elasticsearch
   */
  async indexFinding(finding: UnifiedFinding): Promise<void> {
    if (!this.isAvailable()) {
      return;
    }

    try {
      // Convert finding to ECS format
      const ecsDoc = this.ecsAdapter.toECS(finding);

      // Determine index name (use date-based index for better management)
      const indexName = this.getIndexName('findings');

      // Index the document
      await this.client.index({
        index: indexName,
        body: ecsDoc,
      });

      this.logger.debug(`Indexed finding ${finding.id} to Elasticsearch`);
    } catch (error: any) {
      this.logger.error(`Failed to index finding ${finding.id} to Elasticsearch:`, error);
      // Don't throw - we don't want Elasticsearch failures to break real-time ingestion
    }
  }

  /**
   * Send multiple findings to Elasticsearch (bulk operation)
   */
  async bulkIndexFindings(findings: UnifiedFinding[]): Promise<void> {
    if (!this.isAvailable() || findings.length === 0) {
      return;
    }

    try {
      const indexName = this.getIndexName('findings');
      const body: any[] = [];

      // Prepare bulk operation
      for (const finding of findings) {
        const ecsDoc = this.ecsAdapter.toECS(finding);
        body.push({ index: { _index: indexName } });
        body.push(ecsDoc);
      }

      // Execute bulk operation
      const response = await this.client.bulk({ body });

      if (response.errors) {
        const erroredItems = response.items.filter((item: any) => item.index?.error);
        this.logger.warn(
          `Bulk index had ${erroredItems.length} errors out of ${findings.length} items`
        );
        erroredItems.forEach((item: any) => {
          this.logger.error('Bulk index error:', item.index.error);
        });
      } else {
        this.logger.debug(`Bulk indexed ${findings.length} findings to Elasticsearch`);
      }
    } catch (error: any) {
      this.logger.error(`Failed to bulk index findings to Elasticsearch:`, error);
      // Don't throw - we don't want Elasticsearch failures to break real-time ingestion
    }
  }

  /**
   * Send a real-time event to Elasticsearch
   */
  async indexEvent(
    eventType: string,
    data: any,
    metadata?: Record<string, any>
  ): Promise<void> {
    if (!this.isAvailable()) {
      return;
    }

    try {
      const indexName = this.getIndexName('events');
      const eventDoc: ECSDocument = {
        '@timestamp': new Date().toISOString(),
        'event.kind': 'event',
        'event.category': ['security', 'monitoring'],
        'event.type': [eventType],
        'event.action': eventType,
        'event.severity': this.mapSeverityToECS(data.severity || 'info'),
        'message': data.message || data.title || eventType,
        'tags': ['heimdall', 'realtime', eventType],
        ...metadata,
      };

      await this.client.index({
        index: indexName,
        body: eventDoc,
      });

      this.logger.debug(`Indexed event ${eventType} to Elasticsearch`);
    } catch (error: any) {
      this.logger.error(`Failed to index event ${eventType} to Elasticsearch:`, error);
      // Don't throw - we don't want Elasticsearch failures to break real-time ingestion
    }
  }

  /**
   * Get index name with date pattern
   */
  private getIndexName(type: 'findings' | 'events'): string {
    const date = new Date();
    const dateStr = date.toISOString().split('T')[0].replace(/-/g, '.'); // YYYY.MM.DD
    return `${this.config.indexPrefix}-${type}-${dateStr}`;
  }

  /**
   * Map severity to ECS severity number
   */
  private mapSeverityToECS(severity: string): number {
    const severityMap: Record<string, number> = {
      critical: 1,
      high: 2,
      medium: 3,
      low: 4,
      info: 5,
    };
    return severityMap[severity.toLowerCase()] || 5;
  }

  /**
   * Test Elasticsearch connection
   */
  async testConnection(): Promise<boolean> {
    if (!this.isAvailable()) {
      return false;
    }

    try {
      const response = await this.client.ping();
      return response === true;
    } catch (error: any) {
      this.logger.error('Elasticsearch connection test failed:', error);
      return false;
    }
  }

  /**
   * Get Elasticsearch cluster info
   */
  async getClusterInfo(): Promise<any> {
    if (!this.isAvailable()) {
      return null;
    }

    try {
      const response = await this.client.info();
      return response;
    } catch (error: any) {
      this.logger.error('Failed to get Elasticsearch cluster info:', error);
      return null;
    }
  }
}
