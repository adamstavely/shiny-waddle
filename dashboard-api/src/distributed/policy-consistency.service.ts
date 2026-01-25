import { Injectable } from '@nestjs/common';
import {
  PolicyConsistencyChecker,
  PolicyConsistencyCheckRequest,
  PolicyConsistencyReport,
} from '../../../heimdall-framework/services/policy-consistency-checker.service';
import { RegionConfig } from '../distributed-systems/distributed-systems.service';
import { ApplicationDataService } from '../shared/application-data.service';
import { AppLogger } from '../common/services/logger.service';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface PolicyConsistencyCheckApiRequest {
  applicationId?: string;
  regions?: string[];
  policyIds?: string[];
  checkTypes?: ('version' | 'configuration' | 'evaluation')[];
}

@Injectable()
export class PolicyConsistencyService {
  private readonly reportsFile = path.join(
    process.cwd(),
    '..',
    '..',
    'data',
    'policy-consistency-reports.json'
  );
  private reports: Map<string, PolicyConsistencyReport> = new Map();
  private readonly logger = new AppLogger(PolicyConsistencyService.name);

  constructor(
    private readonly applicationDataService: ApplicationDataService,
  ) {
    this.loadReports().catch(err => {
      this.logger.error('Error loading reports on startup', err);
    });
  }

  /**
   * Check policy consistency across regions
   */
  async checkConsistency(
    request: PolicyConsistencyCheckApiRequest
  ): Promise<PolicyConsistencyReport> {
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
          'At least 2 regions are required for policy consistency checking'
        );
      }

      // Convert RegionConfig to the format expected by PolicyConsistencyChecker
      const regionConfigs = regions.map(region => ({
        id: region.id,
        name: region.name,
        endpoint: region.endpoint,
        pdpEndpoint: region.pdpEndpoint,
        timezone: region.timezone,
        latency: region.latency,
        credentials: region.credentials,
      }));

      // Create consistency checker
      const checker = new PolicyConsistencyChecker();

      // Prepare check request
      const checkRequest: PolicyConsistencyCheckRequest = {
        regions: request.regions || [],
        policyIds: request.policyIds,
        checkTypes: request.checkTypes,
      };

      // Perform consistency check
      const report = await checker.checkConsistency(regionConfigs, checkRequest);

      // Store report
      this.reports.set(report.id, report);
      await this.saveReports();

      this.logger.log(
        `Policy consistency check completed: ${report.consistent ? 'CONSISTENT' : 'INCONSISTENT'} (${report.summary.inconsistentPolicies} inconsistent policies)`
      );

      return report;
    } catch (error: any) {
      this.logger.error(`Error checking policy consistency: ${error.message}`, error.stack);
      throw error;
    }
  }

  /**
   * Get consistency report by ID
   */
  async getConsistencyReport(reportId: string): Promise<PolicyConsistencyReport> {
    const report = this.reports.get(reportId);
    if (!report) {
      throw new Error(`Consistency report ${reportId} not found`);
    }
    return report;
  }

  /**
   * Get all consistency reports
   */
  async getAllReports(): Promise<PolicyConsistencyReport[]> {
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
        reportsArray.map((report: PolicyConsistencyReport) => [
          report.id,
          {
            ...report,
            timestamp: new Date(report.timestamp),
          },
        ])
      );
    } catch (error: any) {
      if (error.code !== 'ENOENT') {
        this.logger.warn('Failed to load consistency reports:', error.message);
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
      this.logger.error('Failed to save consistency reports:', error.message);
    }
  }
}
