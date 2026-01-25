import { Injectable } from '@nestjs/common';
import { MultiRegionTestingService, MultiRegionTestRequest, MultiRegionTestExecutionResult } from '../../../heimdall-framework/services/multi-region-testing.service';
import { RegionConfig } from '../distributed-systems/distributed-systems.service';
import { ApplicationDataService } from '../shared/application-data.service';
import { AppLogger } from '../common/services/logger.service';
import { PolicyDecisionPoint } from '../../../heimdall-framework/services/policy-decision-point';

export interface MultiRegionTestExecutionRequest {
  name: string;
  testType: 'access-control' | 'policy-consistency' | 'synchronization';
  user?: {
    id: string;
    email?: string;
    role?: string;
    attributes?: Record<string, any>;
  };
  resource?: {
    id: string;
    type?: string;
    attributes?: Record<string, any>;
  };
  action?: string;
  regions?: string[];
  expectedResult?: boolean;
  timeout?: number;
  applicationId?: string;
  executionMode?: 'parallel' | 'sequential';
  retryOnFailure?: boolean;
  maxRetries?: number;
}

@Injectable()
export class MultiRegionTestingApiService {
  private readonly logger = new AppLogger(MultiRegionTestingApiService.name);

  constructor(
    private readonly applicationDataService: ApplicationDataService,
  ) {}

  /**
   * Execute multi-region test
   */
  async executeTest(
    request: MultiRegionTestExecutionRequest
  ): Promise<MultiRegionTestExecutionResult> {
    try {
      // Load regions from application infrastructure if applicationId is provided
      let regions: RegionConfig[] = [];
      
      if (request.applicationId) {
        try {
          const application = await this.applicationDataService.findOne(request.applicationId);
          if (application.infrastructure?.distributedSystems) {
            const distSysInfra = application.infrastructure.distributedSystems;
            regions = distSysInfra.regions || [];
          }
        } catch (error) {
          this.logger.warn(
            `Application ${request.applicationId} not found or has no distributed systems infrastructure`
          );
        }
      }

      if (regions.length === 0) {
        throw new Error(
          'No regions configured. Please configure regions in the application infrastructure or provide region configuration.'
        );
      }

      // Convert RegionConfig to the format expected by MultiRegionTestingService
      const regionConfigs = regions.map(region => ({
        id: region.id,
        name: region.name,
        endpoint: region.endpoint,
        pdpEndpoint: region.pdpEndpoint,
        timezone: region.timezone,
        latency: region.latency,
        credentials: region.credentials,
      }));

      // Create multi-region testing service configuration
      const config = {
        regions: regionConfigs,
        executionMode: request.executionMode || 'parallel',
        timeout: request.timeout || 30000,
        retryOnFailure: request.retryOnFailure || false,
        maxRetries: request.maxRetries || 3,
        coordination: {
          type: 'custom' as const,
        },
      };

      // Initialize PDP (optional - can be configured per region)
      const pdp = new PolicyDecisionPoint({
        policyEngine: 'custom',
        cacheDecisions: true,
      });

      // Create multi-region testing service
      const multiRegionService = new MultiRegionTestingService(config, pdp);

      // Convert request to framework format
      const frameworkRequest: MultiRegionTestRequest = {
        name: request.name,
        testType: request.testType,
        user: request.user
          ? {
              id: request.user.id,
              email: request.user.email,
              role: request.user.role,
              attributes: request.user.attributes,
            }
          : undefined,
        resource: request.resource
          ? {
              id: request.resource.id,
              type: request.resource.type,
              attributes: request.resource.attributes,
            }
          : undefined,
        action: request.action,
        regions: request.regions,
        expectedResult: request.expectedResult,
        timeout: request.timeout,
      };

      // Execute test
      const result = await multiRegionService.executeMultiRegionTest(frameworkRequest);

      this.logger.log(
        `Multi-region test "${request.name}" completed: ${result.passed ? 'PASSED' : 'FAILED'}`
      );

      return result;
    } catch (error: any) {
      this.logger.error(`Error executing multi-region test: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Get test execution status
   */
  async getExecutionStatus(testId: string): Promise<any> {
    // In a real implementation, this would track test executions
    // and return status for a specific test execution
    throw new Error('Test execution status tracking not yet implemented');
  }
}
