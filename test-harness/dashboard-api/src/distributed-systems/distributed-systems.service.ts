import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';

export interface RegionConfig {
  id: string;
  name: string;
  endpoint: string;
  pdpEndpoint?: string;
  timezone?: string;
  latency?: number;
  credentials?: Record<string, string>;
}

export interface DistributedTestRequest {
  name: string;
  testType: 'policy-consistency' | 'multi-region' | 'synchronization' | 'transaction' | 'eventual-consistency';
  user?: { id: string };
  resource?: { id: string };
  action?: string;
  regions?: string[];
  timeout?: number;
}

@Injectable()
export class DistributedSystemsService {
  private readonly configPath = path.join(process.cwd(), '..', '..', 'distributed-systems-config.json');
  private regions: RegionConfig[] = [];
  private testResults: any[] = [];

  constructor() {
    this.loadConfig();
  }

  private async loadConfig() {
    try {
      const data = await fs.readFile(this.configPath, 'utf-8');
      const config = JSON.parse(data);
      this.regions = config.regions || [];
      this.testResults = config.testResults || [];
    } catch (error) {
      // Config file doesn't exist, use defaults
      this.regions = [];
      this.testResults = [];
    }
  }

  private async saveConfig() {
    try {
      await fs.writeFile(
        this.configPath,
        JSON.stringify({ regions: this.regions, testResults: this.testResults }, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('Failed to save config:', error);
    }
  }

  async getRegions(): Promise<RegionConfig[]> {
    return this.regions;
  }

  async getRegion(id: string): Promise<RegionConfig | null> {
    return this.regions.find(r => r.id === id) || null;
  }

  async createRegion(region: RegionConfig): Promise<RegionConfig> {
    this.regions.push(region);
    await this.saveConfig();
    return region;
  }

  async updateRegion(id: string, region: Partial<RegionConfig>): Promise<RegionConfig> {
    const index = this.regions.findIndex(r => r.id === id);
    if (index === -1) {
      throw new Error('Region not found');
    }
    this.regions[index] = { ...this.regions[index], ...region };
    await this.saveConfig();
    return this.regions[index];
  }

  async deleteRegion(id: string): Promise<void> {
    const index = this.regions.findIndex(r => r.id === id);
    if (index === -1) {
      throw new Error('Region not found');
    }
    this.regions.splice(index, 1);
    await this.saveConfig();
  }

  async getTestResults(): Promise<any[]> {
    return this.testResults;
  }

  async getTestResult(id: string): Promise<any | null> {
    return this.testResults.find(r => r.id === id) || null;
  }

  async runTest(request: DistributedTestRequest): Promise<any> {
    // In a real implementation, this would use the DistributedSystemsTester
    // For now, create a mock result
    const result = {
      id: `test-${Date.now()}`,
      testName: request.name,
      distributedTestType: request.testType,
      testType: 'distributed-systems',
      passed: Math.random() > 0.3, // 70% pass rate for demo
      timestamp: new Date(),
      regionResults: this.regions.map(region => ({
        regionId: region.id,
        regionName: region.name,
        allowed: Math.random() > 0.2,
        decision: { effect: 'allow', reason: 'Policy evaluation' },
        latency: region.latency || Math.floor(Math.random() * 100) + 50,
        timestamp: new Date(),
      })),
      consistencyCheck: {
        consistent: Math.random() > 0.2,
        inconsistencies: Math.random() > 0.5 ? [] : [
          {
            region1: this.regions[0]?.id || 'region-1',
            region2: this.regions[1]?.id || 'region-2',
            difference: 'Policy evaluation differs',
            severity: 'high',
          },
        ],
      },
      performanceMetrics: {
        totalTime: Math.floor(Math.random() * 500) + 200,
        averageLatency: Math.floor(Math.random() * 100) + 50,
        slowestRegion: this.regions[this.regions.length - 1]?.name || 'Unknown',
        fastestRegion: this.regions[0]?.name || 'Unknown',
      },
    };

    this.testResults.unshift(result);
    await this.saveConfig();
    return result;
  }

  async deleteTestResult(id: string): Promise<void> {
    const index = this.testResults.findIndex(r => r.id === id);
    if (index === -1) {
      throw new Error('Test result not found');
    }
    this.testResults.splice(index, 1);
    await this.saveConfig();
  }
}

