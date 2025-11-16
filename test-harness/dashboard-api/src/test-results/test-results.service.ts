import { Injectable, NotFoundException, Logger, Inject, forwardRef, Optional } from '@nestjs/common';
import { TestResultEntity, QueryFilters, DateRange, ComplianceMetrics } from './entities/test-result.entity';
import { DashboardSSEGateway } from '../dashboard/dashboard-sse.gateway';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class TestResultsService {
  private readonly logger = new Logger(TestResultsService.name);
  private readonly resultsFile = path.join(process.cwd(), 'data', 'test-results.json');
  private results: TestResultEntity[] = [];

  constructor(
    @Inject(forwardRef(() => DashboardSSEGateway))
    @Optional()
    private readonly sseGateway?: DashboardSSEGateway,
  ) {
    this.loadResults().catch(err => {
      this.logger.error('Error loading test results on startup:', err);
    });
  }

  private async loadResults(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.resultsFile, 'utf-8');
        if (!data || data.trim() === '') {
          // Empty file, start with empty array
          this.results = [];
          await this.saveResults();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Test results file does not contain an array, starting with empty array');
          this.results = [];
          await this.saveResults();
          return;
        }
        this.results = parsed.map((r: any) => ({
          ...r,
          timestamp: r.timestamp ? new Date(r.timestamp) : new Date(),
          createdAt: r.createdAt ? new Date(r.createdAt) : new Date(),
          riskAcceptance: r.riskAcceptance ? {
            ...r.riskAcceptance,
            approvedAt: r.riskAcceptance.approvedAt ? new Date(r.riskAcceptance.approvedAt) : undefined,
            expirationDate: r.riskAcceptance.expirationDate ? new Date(r.riskAcceptance.expirationDate) : undefined,
          } : undefined,
          remediation: r.remediation ? {
            ...r.remediation,
            targetDate: r.remediation.targetDate ? new Date(r.remediation.targetDate) : undefined,
            steps: r.remediation.steps?.map((step: any) => ({
              ...step,
              completedAt: step.completedAt ? new Date(step.completedAt) : undefined,
            })),
          } : undefined,
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.results = [];
          await this.saveResults();
        } else if (readError instanceof SyntaxError) {
          // JSON parsing error - file is corrupted
          this.logger.error('JSON parsing error in test results file, starting with empty array:', readError.message);
          this.results = [];
          await this.saveResults();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading test results:', error);
      this.results = [];
    }
  }

  private async saveResults(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      await fs.writeFile(
        this.resultsFile,
        JSON.stringify(this.results, null, 2),
        'utf-8',
      );
    } catch (error) {
      this.logger.error('Error saving test results:', error);
      throw error;
    }
  }

  async saveResult(result: Omit<TestResultEntity, 'id' | 'createdAt'>): Promise<TestResultEntity> {
    const entity: TestResultEntity = {
      ...result,
      id: uuidv4(),
      createdAt: new Date(),
    };

    this.results.unshift(entity); // Add to beginning (newest first)
    await this.saveResults();

    this.logger.log(`Saved test result: ${entity.id} for application ${entity.applicationId}`);
    
    // Broadcast real-time update
    if (this.sseGateway) {
      this.sseGateway.broadcast({
        type: 'test-result',
        data: {
          id: entity.id,
          applicationId: entity.applicationId,
          applicationName: entity.applicationName,
          status: entity.status,
          passed: entity.passed,
          timestamp: entity.timestamp,
        },
        timestamp: new Date(),
      });
    }
    
    return entity;
  }

  async findById(id: string): Promise<TestResultEntity> {
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`Test result with ID "${id}" not found`);
    }
    return result;
  }

  async delete(id: string): Promise<void> {
    await this.loadResults();
    const index = this.results.findIndex(r => r.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test result with ID "${id}" not found`);
    }

    this.results.splice(index, 1);
    await this.saveResults();
    this.logger.log(`Deleted test result: ${id}`);
  }

  async findByApplication(appId: string, filters?: QueryFilters): Promise<TestResultEntity[]> {
    let filtered = this.results.filter(r => r.applicationId === appId);

    if (filters?.status) {
      filtered = filtered.filter(r => r.status === filters.status);
    }

    if (filters?.branch) {
      filtered = filtered.filter(r => r.branch === filters.branch);
    }

    // Sort by timestamp descending (newest first)
    filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Apply pagination
    const offset = filters?.offset || 0;
    const limit = filters?.limit;
    
    if (limit) {
      return filtered.slice(offset, offset + limit);
    }
    
    return filtered.slice(offset);
  }

  async findByTestConfiguration(configId: string, filters?: QueryFilters): Promise<TestResultEntity[]> {
    let filtered = this.results.filter(r => r.testConfigurationId === configId);

    if (filters?.status) {
      filtered = filtered.filter(r => r.status === filters.status);
    }

    if (filters?.branch) {
      filtered = filtered.filter(r => r.branch === filters.branch);
    }

    filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const offset = filters?.offset || 0;
    const limit = filters?.limit;
    
    if (limit) {
      return filtered.slice(offset, offset + limit);
    }
    
    return filtered.slice(offset);
  }

  async findByBuild(buildId: string): Promise<TestResultEntity[]> {
    return this.results
      .filter(r => r.buildId === buildId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async findByDateRange(startDate: Date, endDate: Date, filters?: QueryFilters): Promise<TestResultEntity[]> {
    let filtered = this.results.filter(r => {
      const timestamp = r.timestamp.getTime();
      return timestamp >= startDate.getTime() && timestamp <= endDate.getTime();
    });

    if (filters?.status) {
      filtered = filtered.filter(r => r.status === filters.status);
    }

    if (filters?.branch) {
      filtered = filtered.filter(r => r.branch === filters.branch);
    }

    if (filters?.applicationId) {
      filtered = filtered.filter(r => r.applicationId === filters.applicationId);
    }

    if (filters?.testConfigurationId) {
      filtered = filtered.filter(r => r.testConfigurationId === filters.testConfigurationId);
    }

    filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const offset = filters?.offset || 0;
    const limit = filters?.limit;
    
    if (limit) {
      return filtered.slice(offset, offset + limit);
    }
    
    return filtered.slice(offset);
  }

  async getLatestResult(appId: string, configId: string): Promise<TestResultEntity | null> {
    const result = this.results
      .filter(r => r.applicationId === appId && r.testConfigurationId === configId)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())[0];
    
    return result || null;
  }

  async getComplianceMetrics(
    appId?: string,
    configId?: string,
    dateRange?: DateRange,
  ): Promise<ComplianceMetrics> {
    let filtered = [...this.results];

    // Apply filters
    if (appId) {
      filtered = filtered.filter(r => r.applicationId === appId);
    }

    if (configId) {
      filtered = filtered.filter(r => r.testConfigurationId === configId);
    }

    if (dateRange) {
      filtered = filtered.filter(r => {
        const timestamp = r.timestamp.getTime();
        return timestamp >= dateRange.start.getTime() && timestamp <= dateRange.end.getTime();
      });
    }

    const period = dateRange || {
      start: filtered.length > 0 
        ? new Date(Math.min(...filtered.map(r => r.timestamp.getTime())))
        : new Date(),
      end: filtered.length > 0
        ? new Date(Math.max(...filtered.map(r => r.timestamp.getTime())))
        : new Date(),
    };

    // Calculate overall metrics
    const totalTests = filtered.length;
    const passed = filtered.filter(r => r.status === 'passed').length;
    const failed = filtered.filter(r => r.status === 'failed').length;
    const partial = filtered.filter(r => r.status === 'partial').length;
    const errors = filtered.filter(r => r.status === 'error').length;
    const passRate = totalTests > 0 ? (passed / totalTests) * 100 : 0;
    
    const durations = filtered.filter(r => r.duration !== undefined).map(r => r.duration!);
    const averageDuration = durations.length > 0
      ? durations.reduce((sum, d) => sum + d, 0) / durations.length
      : 0;

    // Calculate trend (compare first half vs second half of period)
    let trend: 'improving' | 'declining' | 'stable' = 'stable';
    if (filtered.length >= 2) {
      const sorted = [...filtered].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());
      const midpoint = Math.floor(sorted.length / 2);
      const firstHalf = sorted.slice(0, midpoint);
      const secondHalf = sorted.slice(midpoint);
      
      const firstHalfPassRate = firstHalf.length > 0
        ? (firstHalf.filter(r => r.status === 'passed').length / firstHalf.length) * 100
        : 0;
      const secondHalfPassRate = secondHalf.length > 0
        ? (secondHalf.filter(r => r.status === 'passed').length / secondHalf.length) * 100
        : 0;
      
      const diff = secondHalfPassRate - firstHalfPassRate;
      if (diff > 5) {
        trend = 'improving';
      } else if (diff < -5) {
        trend = 'declining';
      }
    }

    // Group by test configuration
    const byTestConfiguration: ComplianceMetrics['byTestConfiguration'] = {};
    const configGroups = new Map<string, TestResultEntity[]>();
    
    filtered.forEach(r => {
      if (!configGroups.has(r.testConfigurationId)) {
        configGroups.set(r.testConfigurationId, []);
      }
      configGroups.get(r.testConfigurationId)!.push(r);
    });

    configGroups.forEach((results, configId) => {
      const configPassed = results.filter(r => r.status === 'passed').length;
      const configFailed = results.filter(r => r.status === 'failed').length;
      const configPassRate = results.length > 0 ? (configPassed / results.length) * 100 : 0;
      
      byTestConfiguration[configId] = {
        configName: results[0].testConfigurationName,
        configType: results[0].testConfigurationType,
        totalTests: results.length,
        passed: configPassed,
        failed: configFailed,
        passRate: configPassRate,
      };
    });

    // Identify failing tests
    const failingTestsMap = new Map<string, { count: number; lastFailure: Date }>();
    filtered
      .filter(r => r.status === 'failed' || r.status === 'error')
      .forEach(r => {
        const existing = failingTestsMap.get(r.testConfigurationId);
        if (!existing || r.timestamp > existing.lastFailure) {
          failingTestsMap.set(r.testConfigurationId, {
            count: (existing?.count || 0) + 1,
            lastFailure: r.timestamp,
          });
        } else {
          existing.count++;
        }
      });

    const failingTests = Array.from(failingTestsMap.entries()).map(([configId, data]) => {
      const sample = filtered.find(r => r.testConfigurationId === configId);
      return {
        configId,
        configName: sample?.testConfigurationName || 'Unknown',
        lastFailure: data.lastFailure,
        failureCount: data.count,
      };
    });

    // Calculate trends (daily for now, can be extended)
    const trends: ComplianceMetrics['trends'] = [];
    const dayGroups = new Map<string, TestResultEntity[]>();
    
    filtered.forEach(r => {
      const dayKey = r.timestamp.toISOString().split('T')[0]; // YYYY-MM-DD
      if (!dayGroups.has(dayKey)) {
        dayGroups.set(dayKey, []);
      }
      dayGroups.get(dayKey)!.push(r);
    });

    Array.from(dayGroups.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .forEach(([dayKey, results]) => {
        const dayPassed = results.filter(r => r.status === 'passed').length;
        const dayPassRate = results.length > 0 ? (dayPassed / results.length) * 100 : 0;
        trends.push({
          period: dayKey,
          passRate: dayPassRate,
          totalTests: results.length,
        });
      });

    return {
      period,
      overall: {
        totalTests,
        passed,
        failed,
        partial,
        errors,
        passRate,
        averageDuration,
        trend,
      },
      byTestConfiguration,
      failingTests,
      trends,
    };
  }

  async getTrends(
    appId?: string,
    configId?: string,
    period: 'day' | 'week' | 'month' = 'day',
  ): Promise<Array<{ period: string; passRate: number; totalTests: number }>> {
    let filtered = [...this.results];

    if (appId) {
      filtered = filtered.filter(r => r.applicationId === appId);
    }

    if (configId) {
      filtered = filtered.filter(r => r.testConfigurationId === configId);
    }

    const groups = new Map<string, TestResultEntity[]>();

    filtered.forEach(r => {
      let periodKey: string;
      const date = r.timestamp;
      
      if (period === 'day') {
        periodKey = date.toISOString().split('T')[0]; // YYYY-MM-DD
      } else if (period === 'week') {
        const year = date.getFullYear();
        const week = this.getWeekNumber(date);
        periodKey = `${year}-W${week.toString().padStart(2, '0')}`;
      } else {
        periodKey = `${date.getFullYear()}-${(date.getMonth() + 1).toString().padStart(2, '0')}`; // YYYY-MM
      }

      if (!groups.has(periodKey)) {
        groups.set(periodKey, []);
      }
      groups.get(periodKey)!.push(r);
    });

    return Array.from(groups.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([periodKey, results]) => {
        const passed = results.filter(r => r.status === 'passed').length;
        const passRate = results.length > 0 ? (passed / results.length) * 100 : 0;
        return {
          period: periodKey,
          passRate,
          totalTests: results.length,
        };
      });
  }

  private getWeekNumber(date: Date): number {
    const d = new Date(Date.UTC(date.getFullYear(), date.getMonth(), date.getDate()));
    const dayNum = d.getUTCDay() || 7;
    d.setUTCDate(d.getUTCDate() + 4 - dayNum);
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    return Math.ceil((((d.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
  }

  async deleteOldResults(olderThan: Date): Promise<number> {
    const beforeCount = this.results.length;
    this.results = this.results.filter(r => r.timestamp >= olderThan);
    const afterCount = this.results.length;
    const deleted = beforeCount - afterCount;
    
    if (deleted > 0) {
      await this.saveResults();
      this.logger.log(`Deleted ${deleted} old test results`);
    }
    
    return deleted;
  }

  async query(filters: {
    applicationId?: string;
    testConfigurationId?: string;
    testHarnessId?: string;
    testBatteryId?: string;
    buildId?: string;
    branch?: string;
    status?: TestResultEntity['status'];
    startDate?: Date;
    endDate?: Date;
    limit?: number;
    offset?: number;
  }): Promise<TestResultEntity[]> {
    try {
      // Ensure data is loaded
      if (this.results.length === 0) {
        await this.loadResults();
      }

      let filtered = [...this.results];

      // Filter by harness or battery (requires loading related data)
      if (filters.testHarnessId || filters.testBatteryId) {
        const configIds = await this.getConfigurationIdsForHarnessOrBattery(
          filters.testHarnessId,
          filters.testBatteryId,
        );
        if (configIds.length > 0) {
          filtered = filtered.filter(r => configIds.includes(r.testConfigurationId));
        } else {
          // No matching configs, return empty
          return [];
        }
      }

      if (filters.applicationId) {
        filtered = filtered.filter(r => r.applicationId === filters.applicationId);
      }

      if (filters.testConfigurationId) {
        filtered = filtered.filter(r => r.testConfigurationId === filters.testConfigurationId);
      }

      if (filters.buildId) {
        filtered = filtered.filter(r => r.buildId === filters.buildId);
      }

      if (filters.branch) {
        filtered = filtered.filter(r => r.branch === filters.branch);
      }

      if (filters.status) {
        filtered = filtered.filter(r => r.status === filters.status);
      }

      if (filters.startDate) {
        filtered = filtered.filter(r => r.timestamp >= filters.startDate!);
      }

      if (filters.endDate) {
        filtered = filtered.filter(r => r.timestamp <= filters.endDate!);
      }

      filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

      const offset = filters.offset || 0;
      const limit = filters.limit;

      if (limit) {
        return filtered.slice(offset, offset + limit);
      }

      return filtered.slice(offset);
    } catch (error) {
      this.logger.error('Error in query:', error);
      throw error;
    }
  }

  /**
   * Advanced query with full-text search, complex filtering, and multi-field sorting
   */
  async advancedQuery(options: {
    searchText?: string;
    filters?: Array<{
      field: string;
      operator: 'equals' | 'contains' | 'startsWith' | 'endsWith' | 'greaterThan' | 'lessThan' | 'in' | 'notIn';
      value: any;
      logic?: 'AND' | 'OR';
    }>;
    sort?: Array<{
      field: string;
      direction: 'asc' | 'desc';
    }>;
    limit?: number;
    offset?: number;
  }): Promise<TestResultEntity[]> {
    try {
      if (this.results.length === 0) {
        await this.loadResults();
      }

      let filtered = [...this.results];

      // Full-text search
      if (options.searchText) {
        const searchLower = options.searchText.toLowerCase();
        filtered = filtered.filter(result => {
          const searchableText = [
            result.testConfigurationName,
            result.applicationName,
            result.status,
            result.branch,
            result.buildId,
            result.commitSha,
            result.error?.message,
            JSON.stringify(result.result),
          ].join(' ').toLowerCase();
          return searchableText.includes(searchLower);
        });
      }

      // Advanced filtering
      if (options.filters && options.filters.length > 0) {
        filtered = filtered.filter(result => {
          let matches = true;
          let lastLogic: 'AND' | 'OR' = 'AND';

          for (const filter of options.filters!) {
            const fieldValue = this.getFieldValue(result, filter.field);
            const filterMatches = this.evaluateFilter(fieldValue, filter.operator, filter.value);

            if (lastLogic === 'AND') {
              matches = matches && filterMatches;
            } else {
              matches = matches || filterMatches;
            }

            lastLogic = filter.logic || 'AND';
          }

          return matches;
        });
      }

      // Multi-field sorting
      if (options.sort && options.sort.length > 0) {
        filtered.sort((a, b) => {
          for (const sortOption of options.sort!) {
            const aValue = this.getFieldValue(a, sortOption.field);
            const bValue = this.getFieldValue(b, sortOption.field);
            
            let comparison = 0;
            if (aValue < bValue) {
              comparison = -1;
            } else if (aValue > bValue) {
              comparison = 1;
            }

            if (comparison !== 0) {
              return sortOption.direction === 'asc' ? comparison : -comparison;
            }
          }
          return 0;
        });
      } else {
        // Default sort by timestamp descending
        filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
      }

      // Pagination
      const offset = options.offset || 0;
      const limit = options.limit;

      if (limit) {
        return filtered.slice(offset, offset + limit);
      }

      return filtered.slice(offset);
    } catch (error) {
      this.logger.error('Error in advanced query:', error);
      throw error;
    }
  }

  /**
   * Get field value from result object (supports nested fields)
   */
  private getFieldValue(result: TestResultEntity, field: string): any {
    const parts = field.split('.');
    let value: any = result;
    
    for (const part of parts) {
      if (value && typeof value === 'object' && part in value) {
        value = value[part];
      } else {
        return undefined;
      }
    }
    
    return value;
  }

  /**
   * Evaluate a filter condition
   */
  private evaluateFilter(fieldValue: any, operator: string, filterValue: any): boolean {
    if (fieldValue === undefined || fieldValue === null) {
      return false;
    }

    const fieldStr = String(fieldValue).toLowerCase();
    const filterStr = String(filterValue).toLowerCase();

    switch (operator) {
      case 'equals':
        return fieldValue === filterValue;
      case 'contains':
        return fieldStr.includes(filterStr);
      case 'startsWith':
        return fieldStr.startsWith(filterStr);
      case 'endsWith':
        return fieldStr.endsWith(filterStr);
      case 'greaterThan':
        return fieldValue > filterValue;
      case 'lessThan':
        return fieldValue < filterValue;
      case 'in':
        return Array.isArray(filterValue) && filterValue.includes(fieldValue);
      case 'notIn':
        return Array.isArray(filterValue) && !filterValue.includes(fieldValue);
      default:
        return false;
    }
  }

  /**
   * Export test results to CSV
   */
  async exportToCSV(filters?: {
    applicationId?: string;
    testConfigurationId?: string;
    status?: TestResultStatus;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<string> {
    const results = filters ? await this.query(filters) : [...this.results];

    const headers = [
      'ID',
      'Application ID',
      'Application Name',
      'Test Configuration ID',
      'Test Configuration Name',
      'Status',
      'Passed',
      'Build ID',
      'Branch',
      'Commit SHA',
      'Timestamp',
      'Duration (ms)',
      'Error Message',
    ];

    const rows = results.map(result => [
      result.id,
      result.applicationId,
      result.applicationName,
      result.testConfigurationId,
      result.testConfigurationName,
      result.status,
      result.passed ? 'true' : 'false',
      result.buildId || '',
      result.branch || '',
      result.commitSha || '',
      result.timestamp.toISOString(),
      result.duration?.toString() || '',
      result.error?.message || '',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')),
    ].join('\n');

    return csvContent;
  }

  /**
   * Export test results to JSON
   */
  async exportToJSON(filters?: {
    applicationId?: string;
    testConfigurationId?: string;
    status?: TestResultStatus;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<string> {
    const results = filters ? await this.query(filters) : [...this.results];
    return JSON.stringify(results, null, 2);
  }

  private async getConfigurationIdsForHarnessOrBattery(
    harnessId?: string,
    batteryId?: string,
  ): Promise<string[]> {
    const configIds = new Set<string>();

    try {
      if (batteryId) {
        // Load battery data
        const batteryFile = path.join(process.cwd(), 'dashboard-api', 'data', 'test-batteries.json');
        const batteryData = await fs.readFile(batteryFile, 'utf-8');
        const batteries = JSON.parse(batteryData);
        const battery = Array.isArray(batteries) 
          ? batteries.find((b: any) => b.id === batteryId)
          : null;

        if (!battery || !battery.harnessIds) {
          return [];
        }

        // Get all harnesses in the battery
        for (const hId of battery.harnessIds) {
          const harnessConfigIds = await this.getConfigurationIdsForHarness(hId);
          harnessConfigIds.forEach(id => configIds.add(id));
        }
      } else if (harnessId) {
        // Get configs for single harness
        const harnessConfigIds = await this.getConfigurationIdsForHarness(harnessId);
        harnessConfigIds.forEach(id => configIds.add(id));
      }
    } catch (error) {
      this.logger.error('Error loading harness/battery data:', error);
      return [];
    }

    return Array.from(configIds);
  }

  private async getConfigurationIdsForHarness(harnessId: string): Promise<string[]> {
    const configIds = new Set<string>();

    try {
      // Load harness data
      const harnessFile = path.join(process.cwd(), 'dashboard-api', 'data', 'test-harnesses.json');
      const harnessData = await fs.readFile(harnessFile, 'utf-8');
      const harnesses = JSON.parse(harnessData);
      const harness = Array.isArray(harnesses)
        ? harnesses.find((h: any) => h.id === harnessId)
        : null;

      if (!harness || !harness.testSuiteIds) {
        return [];
      }

      // Load suite data to get configuration IDs
      const suiteFile = path.join(process.cwd(), 'dashboard-api', 'data', 'test-suites.json');
      const suiteData = await fs.readFile(suiteFile, 'utf-8');
      const suites = JSON.parse(suiteData);
      const suiteArray = Array.isArray(suites) ? suites : [];

      // Get all configs from suites in this harness
      for (const suiteId of harness.testSuiteIds) {
        const suite = suiteArray.find((s: any) => s.id === suiteId);
        if (suite && suite.testConfigurationIds) {
          suite.testConfigurationIds.forEach((id: string) => configIds.add(id));
        }
      }
    } catch (error) {
      this.logger.error('Error loading harness/suite data:', error);
      return [];
    }

    return Array.from(configIds);
  }

  async acceptRisk(
    id: string,
    data: {
      reason: string;
      approver: string;
      expirationDate?: Date;
      ticketLink?: string;
    },
  ): Promise<TestResultEntity> {
    await this.loadResults();
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`Test result with ID "${id}" not found`);
    }

    result.riskAcceptance = {
      accepted: true,
      reason: data.reason,
      approver: data.approver,
      approvedAt: new Date(),
      expirationDate: data.expirationDate,
      ticketLink: data.ticketLink,
      rejected: false,
    };

    await this.saveResults();
    this.logger.log(`Risk accepted for test result: ${id} by ${data.approver}`);
    return result;
  }

  async rejectRisk(
    id: string,
    data: {
      reason: string;
      approver: string;
    },
  ): Promise<TestResultEntity> {
    await this.loadResults();
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`Test result with ID "${id}" not found`);
    }

    if (result.riskAcceptance) {
      result.riskAcceptance.accepted = false;
      result.riskAcceptance.rejected = true;
      result.riskAcceptance.rejectionReason = data.reason;
      result.riskAcceptance.approver = data.approver;
    } else {
      result.riskAcceptance = {
        accepted: false,
        rejected: true,
        rejectionReason: data.reason,
        approver: data.approver,
      };
    }

    await this.saveResults();
    this.logger.log(`Risk rejected for test result: ${id} by ${data.approver}`);
    return result;
  }

  async updateRemediation(
    id: string,
    data: {
      status?: 'not-started' | 'in-progress' | 'completed';
      ticketLink?: string;
      assignedTo?: string;
      targetDate?: Date;
      notes?: string;
      progress?: number;
      steps?: Array<{
        step: string;
        status: 'pending' | 'in-progress' | 'completed';
        completedAt?: Date;
      }>;
    },
  ): Promise<TestResultEntity> {
    await this.loadResults();
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`Test result with ID "${id}" not found`);
    }

    if (!result.remediation) {
      result.remediation = {
        status: 'not-started',
        progress: 0,
      };
    }

    if (data.status !== undefined) {
      result.remediation.status = data.status;
    }
    if (data.ticketLink !== undefined) {
      result.remediation.ticketLink = data.ticketLink;
    }
    if (data.assignedTo !== undefined) {
      result.remediation.assignedTo = data.assignedTo;
    }
    if (data.targetDate !== undefined) {
      result.remediation.targetDate = data.targetDate;
    }
    if (data.notes !== undefined) {
      result.remediation.notes = data.notes;
    }
    if (data.progress !== undefined) {
      result.remediation.progress = data.progress;
    }
    if (data.steps !== undefined) {
      result.remediation.steps = data.steps;
    }

    // Auto-update status based on progress
    if (data.progress !== undefined) {
      if (data.progress === 0) {
        result.remediation.status = 'not-started';
      } else if (data.progress === 100) {
        result.remediation.status = 'completed';
      } else if (result.remediation.status === 'not-started') {
        result.remediation.status = 'in-progress';
      }
    }

    await this.saveResults();
    this.logger.log(`Remediation updated for test result: ${id}`);
    return result;
  }
}

