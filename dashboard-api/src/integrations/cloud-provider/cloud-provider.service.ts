import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { MultiCloudIntegration, CloudProviderConfig, MultiCloudFinding, CloudProviderSummary } from '../../../../heimdall-framework/services/multi-cloud-integration';

@Injectable()
export class CloudProviderService {
  private readonly configFile = path.join(process.cwd(), '..', 'data', 'cloud-provider-integrations.json');
  private multiCloud: MultiCloudIntegration = new MultiCloudIntegration();
  private configs: Map<string, CloudProviderConfig> = new Map();

  constructor() {
    this.loadConfig();
  }

  private async loadConfig(): Promise<void> {
    try {
      const data = await fs.readFile(this.configFile, 'utf-8');
      const configs: CloudProviderConfig[] = JSON.parse(data);
      configs.forEach(config => {
        this.configs.set(config.provider, config);
        this.multiCloud.registerProvider(config);
      });
    } catch {
      // File doesn't exist, start with empty config
    }
  }

  private async saveConfig(): Promise<void> {
    try {
      const dir = path.dirname(this.configFile);
      await fs.mkdir(dir, { recursive: true });
      const configs = Array.from(this.configs.values());
      await fs.writeFile(this.configFile, JSON.stringify(configs, null, 2));
    } catch (error) {
      console.error('Error saving cloud provider config:', error);
      throw error;
    }
  }

  async createProvider(config: CloudProviderConfig): Promise<CloudProviderConfig> {
    this.configs.set(config.provider, config);
    this.multiCloud.registerProvider(config);
    await this.saveConfig();
    return config;
  }

  async findAllProviders(): Promise<CloudProviderConfig[]> {
    return Array.from(this.configs.values());
  }

  async findOneProvider(provider: string): Promise<CloudProviderConfig> {
    const config = this.configs.get(provider as 'aws' | 'azure' | 'gcp');
    if (!config) {
      throw new NotFoundException(`Cloud provider ${provider} not found`);
    }
    return config;
  }

  async updateProvider(provider: string, updates: Partial<CloudProviderConfig>): Promise<CloudProviderConfig> {
    const existing = this.configs.get(provider as 'aws' | 'azure' | 'gcp');
    if (!existing) {
      throw new NotFoundException(`Cloud provider ${provider} not found`);
    }

    const updated = { ...existing, ...updates };
    this.configs.set(provider as 'aws' | 'azure' | 'gcp', updated);
    this.multiCloud.registerProvider(updated);
    await this.saveConfig();
    return updated;
  }

  async deleteProvider(provider: string): Promise<void> {
    if (!this.configs.has(provider as 'aws' | 'azure' | 'gcp')) {
      throw new NotFoundException(`Cloud provider ${provider} not found`);
    }
    this.configs.delete(provider as 'aws' | 'azure' | 'gcp');
    await this.saveConfig();
  }

  async normalizeFindings(provider: string, rawFindings: any[]): Promise<any[]> {
    return await this.multiCloud.normalizeProviderFindings(provider as 'aws' | 'azure' | 'gcp', rawFindings);
  }

  async aggregateFindings(providerFindings: Record<string, any[]>): Promise<MultiCloudFinding[]> {
    const findingsMap = new Map<'aws' | 'azure' | 'gcp', any[]>();
    Object.entries(providerFindings).forEach(([provider, findings]) => {
      findingsMap.set(provider as 'aws' | 'azure' | 'gcp', findings);
    });
    return await this.multiCloud.aggregateFindings(findingsMap);
  }

  async getProviderSummaries(findings: MultiCloudFinding[]): Promise<Map<string, CloudProviderSummary>> {
    return await this.multiCloud.getProviderSummaries(findings);
  }

  async findCrossCloudDuplicates(findings: MultiCloudFinding[]): Promise<Map<string, MultiCloudFinding[]>> {
    return this.multiCloud.findCrossCloudDuplicates(findings);
  }
}

