import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { TestResultsService } from '../test-results/test-results.service';
import { TestBatteriesService } from '../test-batteries/test-batteries.service';
import { TestHarnessesService } from '../test-harnesses/test-harnesses.service';
import { TestSuitesService } from '../test-suites/test-suites.service';

@Injectable()
export class RunsService {
  private readonly logger = new Logger(RunsService.name);

  constructor(
    private readonly testResultsService: TestResultsService,
    private readonly testBatteriesService: TestBatteriesService,
    private readonly testHarnessesService: TestHarnessesService,
    private readonly testSuitesService: TestSuitesService,
  ) {}

  async findAll(filters: {
    applicationId?: string;
    batteryId?: string;
    startDate?: Date;
    endDate?: Date;
    limit?: number;
  }): Promise<any[]> {
    try {
      // Get test results with filters
      const queryFilters: any = {
        applicationId: filters.applicationId,
        startDate: filters.startDate,
        endDate: filters.endDate,
        limit: filters.limit,
      };

      // If filtering by battery, we need to find harnesses in that battery
      if (filters.batteryId) {
        const battery = await this.testBatteriesService.findOne(filters.batteryId);
        if (battery && battery.harnessIds) {
          // Get all harnesses for this battery
          const harnesses = await Promise.all(
            battery.harnessIds.map(id => this.testHarnessesService.findOne(id))
          );
          const validHarnesses = harnesses.filter(h => h !== null);
          
          // Get test configuration IDs from these harnesses
          const configIds: string[] = [];
          for (const harness of validHarnesses) {
            if (harness?.testSuiteIds) {
              // We'd need to get suites and their test configs
              // For now, we'll filter by battery metadata in results
            }
          }
        }
      }

      const results = await this.testResultsService.query(queryFilters);

      // Group results by runId to create battery runs
      const runsByRunId = new Map<string, any>();

      for (const result of results) {
        const runId = result.runId || result.id;
        if (!runsByRunId.has(runId)) {
          // Try to find battery name from metadata or by looking up harnesses
          let batteryName = result.metadata?.batteryName || 'Unknown Battery';
          let batteryId = result.metadata?.batteryId;

          // If we have a harness ID, try to find which battery it belongs to
          if (!batteryId && result.metadata?.harnessId) {
            const allBatteries = await this.testBatteriesService.findAll();
            const battery = allBatteries.find(b => 
              b.harnessIds?.includes(result.metadata.harnessId)
            );
            if (battery) {
              batteryName = battery.name;
              batteryId = battery.id;
            }
          }

          runsByRunId.set(runId, {
            id: runId,
            batteryId,
            batteryName,
            applicationId: result.applicationId,
            applicationName: result.applicationName,
            status: result.status === 'passed' ? 'completed' : result.status === 'failed' ? 'failed' : 'running',
            score: this.calculateScoreFromResults([result]),
            timestamp: result.timestamp,
            environment: result.metadata?.environment || 'N/A',
            harnesses: [],
          });
        }

        const run = runsByRunId.get(runId);
        if (result.metadata?.harnessName && !run.harnesses.find((h: any) => h.id === result.metadata.harnessId)) {
          run.harnesses.push({
            id: result.metadata.harnessId,
            name: result.metadata.harnessName,
          });
        }

        // Update score based on all results in this run
        const runResults = results.filter(r => (r.runId || r.id) === runId);
        run.score = this.calculateScoreFromResults(runResults);
      }

      return Array.from(runsByRunId.values()).sort((a, b) => 
        b.timestamp.getTime() - a.timestamp.getTime()
      );
    } catch (error) {
      this.logger.error('Error in findAll:', error);
      throw error;
    }
  }

  async findOne(runId: string): Promise<any> {
    try {
      // Get all test results - we'll filter by runId from metadata
      const allResults = await this.testResultsService.query({});
      
      // Filter results by runId (check both runId field and metadata.runId)
      const results = allResults.filter(r => 
        (r as any).runId === runId || 
        r.metadata?.runId === runId ||
        r.id === runId // Fallback: if runId matches a result ID
      );

      if (results.length === 0) {
        throw new NotFoundException(`Run with ID ${runId} not found`);
      }

      // Get battery info from first result
      const firstResult = results[0];
      let batteryId = firstResult.metadata?.batteryId;
      let batteryName = firstResult.metadata?.batteryName || 'Unknown Battery';

      // If battery ID not in metadata, try to find it
      if (!batteryId && firstResult.metadata?.harnessId) {
        const allBatteries = await this.testBatteriesService.findAll();
        const battery = allBatteries.find(b => 
          b.harnessIds?.includes(firstResult.metadata.harnessId)
        );
        if (battery) {
          batteryId = battery.id;
          batteryName = battery.name;
        }
      }

      // Get battery details if we have the ID
      let battery: any = null;
      if (batteryId) {
        try {
          battery = await this.testBatteriesService.findOne(batteryId);
        } catch (e) {
          this.logger.warn(`Could not find battery ${batteryId}`);
        }
      }

      // Group results by harness
      const harnessMap = new Map<string, any>();
      
      for (const result of results) {
        const harnessId = result.metadata?.harnessId;
        if (!harnessId) continue;

        if (!harnessMap.has(harnessId)) {
          let harness: any = null;
          try {
            harness = await this.testHarnessesService.findOne(harnessId);
          } catch (e) {
            this.logger.warn(`Could not find harness ${harnessId}`);
            continue;
          }

          harnessMap.set(harnessId, {
            id: harness.id,
            name: harness.name || result.metadata?.harnessName || 'Unknown Harness',
            description: harness.description,
            testType: harness.testType,
            suites: [],
          });
        }

        const harnessData = harnessMap.get(harnessId);
        
        // Group by suite
        const suiteId = result.metadata?.suiteId;
        if (suiteId) {
          let suiteData = harnessData.suites.find((s: any) => s.id === suiteId);
          if (!suiteData) {
            let suite: any = null;
            try {
              suite = await this.testSuitesService.findOne(suiteId);
            } catch (e) {
              this.logger.warn(`Could not find suite ${suiteId}`);
              suite = { id: suiteId, name: result.metadata?.suiteName || 'Unknown Suite' };
            }

            suiteData = {
              id: suite.id,
              name: suite.name || result.metadata?.suiteName || 'Unknown Suite',
              testType: suite.testType,
              tests: [],
            };
            harnessData.suites.push(suiteData);
          }

          // Add test result
          suiteData.tests.push({
            id: result.id,
            testConfigurationId: result.testConfigurationId,
            testConfigurationName: result.testConfigurationName || result.testConfigurationType,
            testConfigurationType: result.testConfigurationType,
            status: result.status,
            error: result.error,
            timestamp: result.timestamp,
            duration: result.duration,
            metadata: result.metadata,
          });
        }
      }

      const harnesses = Array.from(harnessMap.values());

      // Calculate overall score
      const score = this.calculateScoreFromResults(results);

      return {
        id: runId,
        batteryId,
        batteryName,
        battery,
        applicationId: firstResult.applicationId,
        applicationName: firstResult.applicationName,
        status: results.every(r => r.status === 'passed') ? 'completed' 
          : results.some(r => r.status === 'failed') ? 'failed' 
          : 'running',
        score,
        timestamp: firstResult.timestamp,
        environment: firstResult.metadata?.environment || 'N/A',
        harnesses,
        totalTests: results.length,
        passedTests: results.filter(r => r.status === 'passed').length,
        failedTests: results.filter(r => r.status === 'failed').length,
      };
    } catch (error) {
      this.logger.error(`Error in findOne for run ${runId}:`, error);
      throw error;
    }
  }

  private calculateScoreFromResults(results: any[]): number {
    if (results.length === 0) return 0;
    const passed = results.filter(r => r.status === 'passed').length;
    return Math.round((passed / results.length) * 100);
  }
}

