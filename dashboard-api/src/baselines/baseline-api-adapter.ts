/**
 * Baseline API Adapter
 * 
 * Provides backward compatibility by mapping baseline API endpoints
 * to test suite endpoints. This allows existing baseline clients to
 * continue working while we migrate to the unified test model.
 * 
 * @deprecated Use test suite APIs instead: /api/v1/test-suites
 */

import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { TestSuitesService } from '../test-suites/test-suites.service';
import { TestSuiteEntity } from '../test-suites/entities/test-suite.entity';

@Injectable()
export class BaselineApiAdapter {
  private readonly logger = new Logger(BaselineApiAdapter.name);

  constructor(private readonly testSuitesService: TestSuitesService) {}

  /**
   * Map platform baseline endpoints to test suite endpoints
   * 
   * GET /api/v1/{platform}/baselines
   *   → GET /api/v1/test-suites?testType={platform}-config
   */
  async listBaselines(platform: string): Promise<any[]> {
    this.logger.warn(
      `[DEPRECATED] Baseline API used: GET /api/v1/${platform}/baselines. ` +
      `Use GET /api/v1/test-suites?testType=${platform}-config instead`
    );

    const testType = this.mapPlatformToTestType(platform);
    const suites = await this.testSuitesService.findAll();
    
    // Filter by test type and convert to baseline format
    return suites
      .filter(s => s.testType === testType && s.baselineConfig)
      .map(s => this.convertTestSuiteToBaseline(s));
  }

  /**
   * GET /api/v1/{platform}/baselines/:id
   *   → GET /api/v1/test-suites/:id
   */
  async getBaseline(platform: string, id: string): Promise<any> {
    this.logger.warn(
      `[DEPRECATED] Baseline API used: GET /api/v1/${platform}/baselines/${id}. ` +
      `Use GET /api/v1/test-suites/${id} instead`
    );

    const suite = await this.testSuitesService.findOne(id);
    if (!suite.baselineConfig) {
      throw new NotFoundException(`Baseline ${id} not found`);
    }

    return this.convertTestSuiteToBaseline(suite);
  }

  /**
   * POST /api/v1/{platform}/baselines/:id/validate
   *   → POST /api/v1/test-suites/:id/run
   */
  async validateBaseline(platform: string, id: string): Promise<any> {
    this.logger.warn(
      `[DEPRECATED] Baseline API used: POST /api/v1/${platform}/baselines/${id}/validate. ` +
      `Use POST /api/v1/test-suites/${id}/run instead`
    );

    const result = await this.testSuitesService.runTestSuite(id);
    
    // Convert to baseline validation format
    return {
      baselineId: id,
      baselineName: result.suiteName,
      status: result.status,
      totalTests: result.totalTests,
      passed: result.passed,
      failed: result.failed,
      results: result.results,
      timestamp: result.timestamp,
    };
  }

  /**
   * Map platform name to test type
   */
  private mapPlatformToTestType(platform: string): string {
    const mapping: Record<string, string> = {
      'salesforce': 'salesforce-config',
      'elastic': 'elastic-config',
      'idp-kubernetes': 'idp-compliance',
      'servicenow': 'servicenow-config',
    };
    return mapping[platform] || `${platform}-config`;
  }

  /**
   * Convert TestSuiteEntity to baseline format (for backward compatibility)
   */
  private convertTestSuiteToBaseline(suite: TestSuiteEntity): any {
    const baselineConfig = (suite as any).baselineConfig;
    if (!baselineConfig) {
      return null;
    }

    return {
      id: suite.id,
      name: suite.name,
      description: suite.description || '',
      environment: baselineConfig.environment,
      version: baselineConfig.version,
      platform: baselineConfig.platform,
      config: baselineConfig.config,
      createdAt: suite.createdAt,
      updatedAt: suite.updatedAt,
      createdBy: suite.createdBy,
      isActive: suite.enabled,
      // Include validation rules if available (from tests)
      validationRules: [], // Will be populated from tests if needed
    };
  }
}
