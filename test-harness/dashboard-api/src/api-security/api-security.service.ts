import { Injectable, NotFoundException } from '@nestjs/common';
import {
  CreateAPISecurityConfigDto,
  CreateAPIEndpointDto,
  CreateAPISecurityTestDto,
  UpdateAPISecurityConfigDto,
} from './dto/create-api-security.dto';
import {
  APISecurityTestConfigEntity,
  APIEndpointEntity,
  APISecurityTestResultEntity,
} from './entities/api-security.entity';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class ApiSecurityService {
  private readonly configsFile = path.join(process.cwd(), '..', '..', 'data', 'api-security-configs.json');
  private readonly endpointsFile = path.join(process.cwd(), '..', '..', 'data', 'api-security-endpoints.json');
  private readonly resultsFile = path.join(process.cwd(), '..', '..', 'data', 'api-security-results.json');

  private configs: APISecurityTestConfigEntity[] = [];
  private endpoints: APIEndpointEntity[] = [];
  private results: APISecurityTestResultEntity[] = [];

  constructor() {
    this.loadData().catch(err => {
      console.error('Error loading API security data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    await Promise.all([
      this.loadConfigs(),
      this.loadEndpoints(),
      this.loadResults(),
    ]);
  }

  private async loadConfigs(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.configsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.configs = (Array.isArray(parsed) ? parsed : []).map((c: any) => ({
          ...c,
          createdAt: new Date(c.createdAt),
          updatedAt: new Date(c.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.configs = [];
          await this.saveConfigs();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading API security configs:', error);
      this.configs = [];
    }
  }

  private async loadEndpoints(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.endpointsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.endpointsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.endpoints = (Array.isArray(parsed) ? parsed : []).map((e: any) => ({
          ...e,
          createdAt: new Date(e.createdAt),
          updatedAt: new Date(e.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.endpoints = [];
          await this.saveEndpoints();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading API endpoints:', error);
      this.endpoints = [];
    }
  }

  private async loadResults(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.resultsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.results = (Array.isArray(parsed) ? parsed : []).map((r: any) => ({
          ...r,
          timestamp: new Date(r.timestamp),
          createdAt: new Date(r.createdAt),
          rateLimitInfo: r.rateLimitInfo ? {
            ...r.rateLimitInfo,
            resetTime: r.rateLimitInfo.resetTime ? new Date(r.rateLimitInfo.resetTime) : undefined,
          } : undefined,
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.results = [];
          await this.saveResults();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading API security results:', error);
      this.results = [];
    }
  }

  private async saveConfigs() {
    try {
      await fs.mkdir(path.dirname(this.configsFile), { recursive: true });
      await fs.writeFile(this.configsFile, JSON.stringify(this.configs, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving API security configs:', error);
      throw error;
    }
  }

  private async saveEndpoints() {
    try {
      await fs.mkdir(path.dirname(this.endpointsFile), { recursive: true });
      await fs.writeFile(this.endpointsFile, JSON.stringify(this.endpoints, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving API endpoints:', error);
      throw error;
    }
  }

  private async saveResults() {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      await fs.writeFile(this.resultsFile, JSON.stringify(this.results, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving API security results:', error);
      throw error;
    }
  }

  // Configs
  async createConfig(dto: CreateAPISecurityConfigDto): Promise<APISecurityTestConfigEntity> {
    const config: APISecurityTestConfigEntity = {
      id: uuidv4(),
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.configs.push(config);
    await this.saveConfigs();

    return config;
  }

  async findAllConfigs(): Promise<APISecurityTestConfigEntity[]> {
    return this.configs;
  }

  async findOneConfig(id: string): Promise<APISecurityTestConfigEntity> {
    const config = this.configs.find(c => c.id === id);
    if (!config) {
      throw new NotFoundException(`API security config with ID "${id}" not found`);
    }
    return config;
  }

  async updateConfig(id: string, dto: UpdateAPISecurityConfigDto): Promise<APISecurityTestConfigEntity> {
    const index = this.configs.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`API security config with ID "${id}" not found`);
    }

    this.configs[index] = {
      ...this.configs[index],
      ...dto,
      updatedAt: new Date(),
    };

    await this.saveConfigs();

    return this.configs[index];
  }

  async removeConfig(id: string): Promise<void> {
    const index = this.configs.findIndex(c => c.id === id);
    if (index === -1) {
      throw new NotFoundException(`API security config with ID "${id}" not found`);
    }

    this.configs.splice(index, 1);
    await this.saveConfigs();

    // Also remove associated endpoints
    this.endpoints = this.endpoints.filter(e => e.configId !== id);
    await this.saveEndpoints();
  }

  // Endpoints
  async createEndpoint(dto: CreateAPIEndpointDto): Promise<APIEndpointEntity> {
    const endpoint: APIEndpointEntity = {
      id: uuidv4(),
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.endpoints.push(endpoint);
    await this.saveEndpoints();

    return endpoint;
  }

  async findAllEndpoints(configId?: string): Promise<APIEndpointEntity[]> {
    if (configId) {
      return this.endpoints.filter(e => e.configId === configId);
    }
    return this.endpoints;
  }

  async findOneEndpoint(id: string): Promise<APIEndpointEntity> {
    const endpoint = this.endpoints.find(e => e.id === id);
    if (!endpoint) {
      throw new NotFoundException(`API endpoint with ID "${id}" not found`);
    }
    return endpoint;
  }

  async removeEndpoint(id: string): Promise<void> {
    const index = this.endpoints.findIndex(e => e.id === id);
    if (index === -1) {
      throw new NotFoundException(`API endpoint with ID "${id}" not found`);
    }

    this.endpoints.splice(index, 1);
    await this.saveEndpoints();
  }

  // Test Results
  async createTestResult(dto: CreateAPISecurityTestDto): Promise<APISecurityTestResultEntity> {
    // In a real implementation, this would execute the actual test
    // For now, we'll create a mock result
    const result: APISecurityTestResultEntity = {
      id: uuidv4(),
      configId: dto.configId,
      endpointId: dto.endpointId,
      testName: dto.testName,
      endpoint: dto.endpoint,
      method: dto.method,
      testType: dto.testType,
      status: 'passed', // Mock status
      timestamp: new Date(),
      createdAt: new Date(),
    };

    this.results.push(result);
    await this.saveResults();

    return result;
  }

  async findAllResults(
    configId?: string,
    endpointId?: string,
    testType?: string,
    status?: string,
  ): Promise<APISecurityTestResultEntity[]> {
    let filtered = [...this.results];

    if (configId) {
      filtered = filtered.filter(r => r.configId === configId);
    }
    if (endpointId) {
      filtered = filtered.filter(r => r.endpointId === endpointId);
    }
    if (testType) {
      filtered = filtered.filter(r => r.testType === testType);
    }
    if (status) {
      filtered = filtered.filter(r => r.status === status);
    }

    return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async findOneResult(id: string): Promise<APISecurityTestResultEntity> {
    const result = this.results.find(r => r.id === id);
    if (!result) {
      throw new NotFoundException(`API security test result with ID "${id}" not found`);
    }
    return result;
  }
}

