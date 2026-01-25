import { Controller, Get, Post, Body } from '@nestjs/common';
import { ElasticsearchService } from './elasticsearch.service';

@Controller('api/v1/elasticsearch')
export class ElasticsearchController {
  constructor(private readonly elasticsearchService: ElasticsearchService) {}

  /**
   * Test Elasticsearch connection
   * GET /api/v1/elasticsearch/test
   */
  @Get('test')
  async testConnection() {
    const isConnected = await this.elasticsearchService.testConnection();
    return {
      enabled: this.elasticsearchService.isAvailable(),
      connected: isConnected,
      message: isConnected
        ? 'Successfully connected to Elasticsearch'
        : 'Failed to connect to Elasticsearch',
    };
  }

  /**
   * Get Elasticsearch cluster info
   * GET /api/v1/elasticsearch/info
   */
  @Get('info')
  async getClusterInfo() {
    const info = await this.elasticsearchService.getClusterInfo();
    return {
      enabled: this.elasticsearchService.isAvailable(),
      info: info || null,
    };
  }

  /**
   * Manually index a finding (for testing)
   * POST /api/v1/elasticsearch/index-finding
   */
  @Post('index-finding')
  async indexFinding(@Body() finding: any) {
    if (!this.elasticsearchService.isAvailable()) {
      return {
        success: false,
        message: 'Elasticsearch is not enabled or client is not available',
      };
    }

    try {
      await this.elasticsearchService.indexFinding(finding);
      return {
        success: true,
        message: 'Finding indexed successfully',
      };
    } catch (error: any) {
      return {
        success: false,
        message: error.message,
      };
    }
  }
}
