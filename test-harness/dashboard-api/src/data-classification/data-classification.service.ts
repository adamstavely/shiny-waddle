import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateClassificationLevelDto } from './dto/create-classification-level.dto';
import { CreateClassificationRuleDto } from './dto/create-classification-rule.dto';

export interface ClassificationLevel {
  id: string;
  name: string;
  description: string;
  sensitivity: 'public' | 'internal' | 'confidential' | 'restricted';
  color: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface ClassificationRule {
  id: string;
  name: string;
  description: string;
  levelId: string;
  pattern?: string;
  field?: string;
  condition: 'contains' | 'equals' | 'matches' | 'starts-with' | 'ends-with';
  value: string;
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class DataClassificationService {
  private readonly logger = new Logger(DataClassificationService.name);
  private readonly dataFile = path.join(process.cwd(), 'data', 'data-classification.json');
  private levels: ClassificationLevel[] = [];
  private rules: ClassificationRule[] = [];

  constructor() {
    this.loadData().catch(err => {
      this.logger.error('Error loading data classification data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      try {
        const data = await fs.readFile(this.dataFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.initializeDefaults();
          await this.saveData();
          return;
        }
        const parsed = JSON.parse(data);
        this.levels = (parsed.levels || []).map((l: any) => ({
          ...l,
          createdAt: l.createdAt ? new Date(l.createdAt) : new Date(),
          updatedAt: l.updatedAt ? new Date(l.updatedAt) : new Date(),
        }));
        this.rules = (parsed.rules || []).map((r: any) => ({
          ...r,
          createdAt: r.createdAt ? new Date(r.createdAt) : new Date(),
          updatedAt: r.updatedAt ? new Date(r.updatedAt) : new Date(),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.initializeDefaults();
          await this.saveData();
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error, initializing defaults:', readError.message);
          this.initializeDefaults();
          await this.saveData();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading data classification data:', error);
      this.initializeDefaults();
    }
  }

  private initializeDefaults(): void {
    this.levels = [
      {
        id: uuidv4(),
        name: 'Public',
        description: 'Publicly accessible data',
        sensitivity: 'public',
        color: '#48bb78',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: uuidv4(),
        name: 'Internal',
        description: 'Internal use only',
        sensitivity: 'internal',
        color: '#4299e1',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: uuidv4(),
        name: 'Confidential',
        description: 'Confidential data requiring protection',
        sensitivity: 'confidential',
        color: '#ed8936',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
      {
        id: uuidv4(),
        name: 'Restricted',
        description: 'Highly restricted data',
        sensitivity: 'restricted',
        color: '#f56565',
        createdAt: new Date(),
        updatedAt: new Date(),
      },
    ];
    this.rules = [];
  }

  private async saveData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      await fs.writeFile(
        this.dataFile,
        JSON.stringify({ levels: this.levels, rules: this.rules }, null, 2),
        'utf-8',
      );
    } catch (error) {
      this.logger.error('Error saving data classification data:', error);
      throw error;
    }
  }

  async getLevels(): Promise<ClassificationLevel[]> {
    await this.loadData();
    return [...this.levels];
  }

  async createLevel(dto: CreateClassificationLevelDto): Promise<ClassificationLevel> {
    await this.loadData();
    const level: ClassificationLevel = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description || '',
      sensitivity: dto.sensitivity,
      color: dto.color || '#4facfe',
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.levels.push(level);
    await this.saveData();
    return level;
  }

  async updateLevel(id: string, dto: Partial<CreateClassificationLevelDto>): Promise<ClassificationLevel> {
    await this.loadData();
    const index = this.levels.findIndex(l => l.id === id);
    if (index === -1) {
      throw new NotFoundException(`Classification level with ID ${id} not found`);
    }
    const existing = this.levels[index];
    this.levels[index] = {
      ...existing,
      name: dto.name !== undefined ? dto.name : existing.name,
      description: dto.description !== undefined ? dto.description : existing.description,
      sensitivity: dto.sensitivity !== undefined ? dto.sensitivity : existing.sensitivity,
      color: dto.color !== undefined ? dto.color : existing.color,
      updatedAt: new Date(),
    };
    await this.saveData();
    return this.levels[index];
  }

  async deleteLevel(id: string): Promise<void> {
    await this.loadData();
    const index = this.levels.findIndex(l => l.id === id);
    if (index === -1) {
      throw new NotFoundException(`Classification level with ID ${id} not found`);
    }
    // Also delete rules associated with this level
    this.rules = this.rules.filter(r => r.levelId !== id);
    this.levels.splice(index, 1);
    await this.saveData();
  }

  async getRules(): Promise<ClassificationRule[]> {
    await this.loadData();
    return [...this.rules];
  }

  async createRule(dto: CreateClassificationRuleDto): Promise<ClassificationRule> {
    await this.loadData();
    const rule: ClassificationRule = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description || '',
      levelId: dto.levelId,
      pattern: dto.pattern,
      field: dto.field,
      condition: dto.condition,
      value: dto.value,
      enabled: dto.enabled !== undefined ? dto.enabled : true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.rules.push(rule);
    await this.saveData();
    return rule;
  }

  async updateRule(id: string, dto: Partial<CreateClassificationRuleDto>): Promise<ClassificationRule> {
    await this.loadData();
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) {
      throw new NotFoundException(`Classification rule with ID ${id} not found`);
    }
    const existing = this.rules[index];
    this.rules[index] = {
      ...existing,
      name: dto.name !== undefined ? dto.name : existing.name,
      description: dto.description !== undefined ? dto.description : existing.description,
      levelId: dto.levelId !== undefined ? dto.levelId : existing.levelId,
      pattern: dto.pattern !== undefined ? dto.pattern : existing.pattern,
      field: dto.field !== undefined ? dto.field : existing.field,
      condition: dto.condition !== undefined ? dto.condition : existing.condition,
      value: dto.value !== undefined ? dto.value : existing.value,
      enabled: dto.enabled !== undefined ? dto.enabled : existing.enabled,
      updatedAt: new Date(),
    };
    await this.saveData();
    return this.rules[index];
  }

  async deleteRule(id: string): Promise<void> {
    await this.loadData();
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) {
      throw new NotFoundException(`Classification rule with ID ${id} not found`);
    }
    this.rules.splice(index, 1);
    await this.saveData();
  }
}

