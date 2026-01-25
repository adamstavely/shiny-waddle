import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateBaselineDto } from './dto/create-baseline.dto';
import { EnvironmentConfigService } from '../environment-config/environment-config.service';

export interface PlatformConfigBaseline {
  id: string;
  name: string;
  description: string;
  environment: string;
  config: Record<string, any>;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
}

@Injectable()
export class PlatformConfigService {
  private readonly logger = new Logger(PlatformConfigService.name);
  private readonly dataFile = path.join(process.cwd(), 'data', 'platform-config-baselines.json');
  private baselines: PlatformConfigBaseline[] = [];

  constructor(private readonly environmentConfigService: EnvironmentConfigService) {
    this.loadData().catch(err => {
      this.logger.error('Error loading platform config data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      try {
        const data = await fs.readFile(this.dataFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.baselines = [];
          try {
            await this.saveData();
          } catch (saveError) {
            // Ignore save errors - data is already set to empty array
            this.logger.warn('Failed to save platform config baselines file, continuing with empty array:', saveError);
          }
          return;
        }
        const parsed = JSON.parse(data);
        this.baselines = (Array.isArray(parsed) ? parsed : []).map((b: any) => ({
          ...b,
          createdAt: b.createdAt ? new Date(b.createdAt) : new Date(),
          updatedAt: b.updatedAt ? new Date(b.updatedAt) : new Date(),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.baselines = [];
          try {
            await this.saveData();
          } catch (saveError) {
            // Ignore save errors - data is already set to empty array
            this.logger.warn('Failed to save platform config baselines file, continuing with empty array:', saveError);
          }
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error, initializing empty:', readError.message);
          this.baselines = [];
          try {
            await this.saveData();
          } catch (saveError) {
            // Ignore save errors - data is already set to empty array
            this.logger.warn('Failed to save platform config baselines file, continuing with empty array:', saveError);
          }
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading platform config data:', error);
      this.baselines = [];
    }
  }

  private async saveData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      await fs.writeFile(this.dataFile, JSON.stringify(this.baselines, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving platform config data:', error);
      throw error;
    }
  }

  async getBaselines(): Promise<PlatformConfigBaseline[]> {
    await this.loadData();
    return [...this.baselines];
  }

  async getBaseline(id: string): Promise<PlatformConfigBaseline> {
    await this.loadData();
    const baseline = this.baselines.find(b => b.id === id);
    if (!baseline) {
      throw new NotFoundException(`Baseline with ID ${id} not found`);
    }
    return baseline;
  }

  async createBaseline(dto: CreateBaselineDto): Promise<PlatformConfigBaseline> {
    await this.loadData();
    const baseline: PlatformConfigBaseline = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description || '',
      environment: dto.environment,
      config: dto.config || {},
      createdBy: dto.createdBy,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.baselines.push(baseline);
    await this.saveData();
    return baseline;
  }

  async updateBaseline(id: string, dto: Partial<CreateBaselineDto>): Promise<PlatformConfigBaseline> {
    await this.loadData();
    const index = this.baselines.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`Baseline with ID ${id} not found`);
    }
    const existing = this.baselines[index];
    this.baselines[index] = {
      ...existing,
      name: dto.name !== undefined ? dto.name : existing.name,
      description: dto.description !== undefined ? dto.description : existing.description,
      environment: dto.environment !== undefined ? dto.environment : existing.environment,
      config: dto.config !== undefined ? dto.config : existing.config,
      createdBy: dto.createdBy !== undefined ? dto.createdBy : existing.createdBy,
      updatedAt: new Date(),
    };
    await this.saveData();
    return this.baselines[index];
  }

  async deleteBaseline(id: string): Promise<void> {
    await this.loadData();
    const index = this.baselines.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`Baseline with ID ${id} not found`);
    }
    this.baselines.splice(index, 1);
    await this.saveData();
  }

  async compareBaseline(id: string, currentConfig: any): Promise<any> {
    const baseline = await this.getBaseline(id);
    // Simple comparison - in production, this would be more sophisticated
    const differences: any[] = [];
    const baselineKeys = Object.keys(baseline.config);
    const currentKeys = Object.keys(currentConfig);

    // Find added keys
    currentKeys.forEach(key => {
      if (!baselineKeys.includes(key)) {
        differences.push({ type: 'added', key, value: currentConfig[key] });
      } else if (JSON.stringify(baseline.config[key]) !== JSON.stringify(currentConfig[key])) {
        differences.push({
          type: 'modified',
          key,
          baselineValue: baseline.config[key],
          currentValue: currentConfig[key],
        });
      }
    });

    // Find removed keys
    baselineKeys.forEach(key => {
      if (!currentKeys.includes(key)) {
        differences.push({ type: 'removed', key, value: baseline.config[key] });
      }
    });

    return {
      baselineId: id,
      baselineName: baseline.name,
      differences,
      hasChanges: differences.length > 0,
    };
  }

  async detectDrift(id: string, currentConfig: any): Promise<any> {
    const comparison = await this.compareBaseline(id, currentConfig);
    // Use environment config service for drift detection if available
    try {
      const baseline = await this.getBaseline(id);
      // Convert config objects to variables format for drift detection
      const baselineVars = this.configToVariables(baseline.config);
      const currentVars = this.configToVariables(currentConfig);
      
      const driftResult = await this.environmentConfigService.detectDrift({
        baselineEnvironment: baseline.environment,
        currentEnvironment: 'current',
        variables: baselineVars,
        currentVariables: currentVars,
      });
      return {
        ...comparison,
        driftDetails: driftResult,
      };
    } catch (error) {
      // Fallback to simple comparison
      this.logger.warn('Error detecting drift with EnvironmentConfigService, using simple comparison:', error);
      return comparison;
    }
  }

  private configToVariables(config: Record<string, any>): Record<string, string> {
    const vars: Record<string, string> = {};
    for (const [key, value] of Object.entries(config)) {
      vars[key] = typeof value === 'string' ? value : JSON.stringify(value);
    }
    return vars;
  }
}

