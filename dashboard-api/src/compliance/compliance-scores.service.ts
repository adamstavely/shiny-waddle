import { Injectable, Logger, Inject, forwardRef } from '@nestjs/common';
import { UnifiedFindingsService } from '../unified-findings/unified-findings.service';
import { TestResultsService } from '../test-results/test-results.service';
import { getDomainFromTestType, getDomainDisplayName } from '../../../heimdall-framework/core/domain-mapping';
import { TestType } from '../../../heimdall-framework/core/types';

@Injectable()
export class ComplianceScoresService {
  private readonly logger = new Logger(ComplianceScoresService.name);

  constructor(
    @Inject(forwardRef(() => UnifiedFindingsService))
    private readonly unifiedFindingsService: UnifiedFindingsService,
    @Inject(forwardRef(() => TestResultsService))
    private readonly testResultsService: TestResultsService,
  ) {}

  async getHistory(filters: {
    applicationId?: string;
    startDate?: Date;
    endDate?: Date;
    days?: number;
    domain?: string;
  }): Promise<Array<{ date: string; score: number; applicationId?: string; applicationName?: string }>> {
    try {
      // Use UnifiedFindingsService to get compliance trends
      const days = filters.days || 30;
      const applicationIds = filters.applicationId ? [filters.applicationId] : undefined;
      
      const trends = await this.unifiedFindingsService.getComplianceTrends(
        days,
        applicationIds,
        undefined,
      );

      // If we have date filters, apply them
      let filtered = trends;
      if (filters.startDate) {
        filtered = filtered.filter(t => new Date(t.date) >= filters.startDate!);
      }
      if (filters.endDate) {
        filtered = filtered.filter(t => new Date(t.date) <= filters.endDate!);
      }

      // If we need application-specific data, enrich with application names
      if (filters.applicationId) {
        return filtered.map(t => ({
          ...t,
          applicationId: filters.applicationId,
        }));
      }

      return filtered;
    } catch (error) {
      this.logger.error('Error getting compliance score history:', error);
      // Fallback: calculate from test results
      return this.getHistoryFromTestResults(filters);
    }
  }

  private async getHistoryFromTestResults(filters: {
    applicationId?: string;
    startDate?: Date;
    endDate?: Date;
    days?: number;
    domain?: string;
  }): Promise<Array<{ date: string; score: number; applicationId?: string }>> {
    try {
      const days = filters.days || 30;
      const endDate = filters.endDate || new Date();
      const startDate = filters.startDate || new Date(Date.now() - days * 24 * 60 * 60 * 1000);

      // Get test results in the date range
      const results = await this.testResultsService.query({
        applicationId: filters.applicationId,
        startDate,
        endDate,
      });

      // Filter by domain if specified
      let filteredResults = results;
      if (filters.domain) {
        const domainMap: Record<string, string> = {
          'data-contracts': 'Data Contracts',
          'iam': 'IAM',
          'api-security': 'API Security',
          'platform-config': 'Platform Config',
        };
        const domainName = domainMap[filters.domain.toLowerCase().replace(/\s+/g, '-')] || filters.domain;
        
        filteredResults = results.filter(result => {
          const testType = (result as any).testConfigurationType || '';
          const resultDomain = this.getDomainFromTestType(testType);
          return resultDomain === domainName;
        });
      }

      // Group by date and calculate scores
      const scoresByDate = new Map<string, { passed: number; total: number }>();

      for (const result of filteredResults) {
        const date = new Date(result.timestamp).toISOString().split('T')[0];
        if (!scoresByDate.has(date)) {
          scoresByDate.set(date, { passed: 0, total: 0 });
        }
        const stats = scoresByDate.get(date)!;
        stats.total++;
        if (result.status === 'passed') {
          stats.passed++;
        }
      }

      // Convert to array format
      const history: Array<{ date: string; score: number; applicationId?: string }> = [];
      for (const [date, stats] of scoresByDate.entries()) {
        const score = stats.total > 0 ? Math.round((stats.passed / stats.total) * 100) : 0;
        history.push({
          date,
          score,
          applicationId: filters.applicationId,
        });
      }

      // Sort by date
      history.sort((a, b) => a.date.localeCompare(b.date));

      return history;
    } catch (error) {
      this.logger.error('Error getting history from test results:', error);
      return [];
    }
  }

  private getDomainFromTestType(testType: string): string {
    // Use centralized domain mapping utility
    try {
      const domain = getDomainFromTestType(testType as TestType);
      return getDomainDisplayName(domain);
    } catch (error) {
      // Fallback for unknown test types
      return 'Other';
    }
  }
}

