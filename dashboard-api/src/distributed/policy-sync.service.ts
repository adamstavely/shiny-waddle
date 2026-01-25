import { Injectable } from '@nestjs/common';
import {
  PolicySyncTester,
  PolicySyncTestRequest,
  PolicySyncReport,
} from '../../../heimdall-framework/services/policy-sync-tester.service';
import { RegionConfig } from '../distributed-systems/distributed-systems.service';
import { ApplicationDataService } from '../shared/application-data.service';
import { AppLogger } from '../common/services/logger.service';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface PolicySyncTestApiRequest {
  applicationId?: string;
  regions?: string[];
  policyId?: string;
  testScenarios?: ('update-propagation' | 'sync-timing' | 'sync-failure-recovery')[];
}

@Injectable()
export class PolicySyncService {
  private readonly reportsFile = path.join(
    process.cwd(),
    '..',
    '..',
    'data',
    'policy-sync-reports.json'
  );
  private reports: Map<string, PolicySyncReport> = new Map();
  private readonly logger = new AppLogger(PolicySyncService.name);

  constructor(
    private readonly applicationDataService: ApplicationDataService,
  ) {
    this.loadReports().catch(err => {
      this.logger.error('Error loading reports on startup', err);
    });
  }

  /**
   * Test policy synchronization
   */
  async testSynchronization(
    request: PolicySyncTestApiRequest
  ): Promise<PolicySyncReport> {
    try {
      // Load regions from application infrastructure
      let regions: RegionConfig[] = [];

      if (request.applicationId) {
        try {
          const application = await this.applicationDataService.findOne(
            request.applicationId
          );
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

      if (regions.length < 2) {
        throw new Error(
          'At least 2 regions are required for policy synchronization testing'
        );
      }

      // Convert RegionConfig to the format expected by PolicySyncTester
      const regionConfigs = regions.map(region => ({
        id: region.id,
        name: region.name,
        endpoint: region.endpoint,
        pdpEndpoint: region.pdpEndpoint,
        timezone: region.timezone,
        latency: region.latency,
        credentials: region.credentials,
      }));

      // Create sync tester
      const tester = new PolicySyncTester();

      // Prepare test request
      const testRequest: PolicySyncTestRequest = {
        regions: request.regions || [],
        policyId: request.policyId,
        testScenarios: request.testScenarios,
      };

      // Perform synchronization test
      const report = await tester.testSynchronization(regionConfigs, testRequest);

      // Store report
      this.reports.set(report.id, report);
      await this.saveReports();

      this.logger.log(
        `Policy synchronization test completed: ${report.summary.passedTests}/${report.summary.totalTests} tests passed`
      );

      return report;
    } catch (error: any) {
      this.logger.error(`Error testing policy synchronization: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Get sync report by ID
   */
  async getSyncReport(reportId: string): Promise<PolicySyncReport> {
    const report = this.reports.get(reportId);
    if (!report) {
      throw new Error(`Sync report ${reportId} not found`);
    }
    return report;
  }

  /**
   * Get all sync reports
   */
  async getAllReports(): Promise<PolicySyncReport[]> {
    return Array.from(this.reports.values());
  }

  /**
   * Load reports from file
   */
  private async loadReports(): Promise<void> {
    try {
      const data = await fs.readFile(this.reportsFile, 'utf-8');
      const reportsArray = JSON.parse(data);
      this.reports = new Map(
        reportsArray.map((report: PolicySyncReport) => [
          report.id,
          {
            ...report,
            timestamp: new Date(report.timestamp),
            testResults: report.testResults.map(result => ({
              ...result,
              timestamp: new Date(result.timestamp),
              details: {
                ...result.details,
                syncEvents: result.details.syncEvents.map(event => ({
                  ...event,
                  timestamp: new Date(event.timestamp),
                })),
                failures: result.details.failures?.map(failure => ({
                  ...failure,
                  timestamp: new Date(failure.timestamp),
                })),
              },
            })),
          },
        ])
      );
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        this.logger.warn('Failed to load sync reports:', error.message);
      }
      this.reports = new Map();
    }
  }

  /**
   * Save reports to file
   */
  private async saveReports(): Promise<void> {
    try {
      const reportsArray = Array.from(this.reports.values());
      await fs.writeFile(
        this.reportsFile,
        JSON.stringify(reportsArray, null, 2),
        'utf-8'
      );
    } catch (error: any) {
      this.logger.error('Failed to save sync reports:', error.message);
    }
  }
}
