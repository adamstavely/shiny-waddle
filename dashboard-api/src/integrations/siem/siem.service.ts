import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { SIEMIntegration, SIEMConfig, BaseSIEMAdapter, SplunkAdapter, QRadarAdapter, SentinelAdapter } from '../../../../services/siem-integration';
import { UnifiedFinding } from '../../../../core/unified-finding-schema';

@Injectable()
export class SIEMService {
  private readonly configFile = path.join(process.cwd(), '..', 'data', 'siem-integrations.json');
  private integrations: Map<string, SIEMConfig> = new Map();
  private siemIntegration: SIEMIntegration = new SIEMIntegration();

  constructor() {
    this.loadConfig();
  }

  private async loadConfig(): Promise<void> {
    try {
      const data = await fs.readFile(this.configFile, 'utf-8');
      const configs: SIEMConfig[] = JSON.parse(data);
      configs.forEach(config => {
        this.integrations.set(config.type, config);
        if (config.enabled) {
          const adapter = this.siemIntegration.createAdapter(config);
          this.siemIntegration.registerAdapter(config.type, adapter);
        }
      });
    } catch {
      // File doesn't exist, start with empty config
    }
  }

  private async saveConfig(): Promise<void> {
    try {
      const dir = path.dirname(this.configFile);
      await fs.mkdir(dir, { recursive: true });
      const configs = Array.from(this.integrations.values());
      await fs.writeFile(this.configFile, JSON.stringify(configs, null, 2));
    } catch (error) {
      console.error('Error saving SIEM config:', error);
      throw error;
    }
  }

  async createIntegration(config: SIEMConfig): Promise<SIEMConfig> {
    const adapter = this.siemIntegration.createAdapter(config);
    const connected = await adapter.testConnection();
    
    if (!connected) {
      throw new BadRequestException('Failed to connect to SIEM system');
    }

    this.integrations.set(config.type, config);
    if (config.enabled) {
      this.siemIntegration.registerAdapter(config.type, adapter);
    }
    await this.saveConfig();

    return config;
  }

  async findAllIntegrations(): Promise<SIEMConfig[]> {
    return Array.from(this.integrations.values());
  }

  async findOneIntegration(type: string): Promise<SIEMConfig> {
    const config = this.integrations.get(type);
    if (!config) {
      throw new NotFoundException(`SIEM integration ${type} not found`);
    }
    return config;
  }

  async updateIntegration(type: string, updates: Partial<SIEMConfig>): Promise<SIEMConfig> {
    const existing = this.integrations.get(type);
    if (!existing) {
      throw new NotFoundException(`SIEM integration ${type} not found`);
    }

    const updated = { ...existing, ...updates };
    this.integrations.set(type, updated);

    if (updated.enabled) {
      const adapter = this.siemIntegration.createAdapter(updated);
      this.siemIntegration.registerAdapter(type, adapter);
    }

    await this.saveConfig();
    return updated;
  }

  async deleteIntegration(type: string): Promise<void> {
    if (!this.integrations.has(type)) {
      throw new NotFoundException(`SIEM integration ${type} not found`);
    }
    this.integrations.delete(type);
    await this.saveConfig();
  }

  async testConnection(type: string): Promise<boolean> {
    const config = this.integrations.get(type);
    if (!config) {
      throw new NotFoundException(`SIEM integration ${type} not found`);
    }

    return await this.siemIntegration.testSIEMConnection(type);
  }

  async sendFinding(type: string, finding: UnifiedFinding): Promise<boolean> {
    const config = this.integrations.get(type);
    if (!config || !config.enabled) {
      throw new NotFoundException(`SIEM integration ${type} not found or not enabled`);
    }

    const results = await this.siemIntegration.sendFindingToAll(finding);
    return results.get(type) || false;
  }

  async queryEvents(type: string, query: string, startTime?: string, endTime?: string): Promise<any> {
    const config = this.integrations.get(type);
    if (!config || !config.enabled) {
      throw new NotFoundException(`SIEM integration ${type} not found or not enabled`);
    }

    const timeRange = startTime && endTime ? {
      start: new Date(startTime),
      end: new Date(endTime),
    } : undefined;

    return await this.siemIntegration.querySIEM(type, query, timeRange);
  }
}

