import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { CreateValidationTargetDto, ValidationTargetStatus } from './dto/create-validation-target.dto';
import { UpdateValidationTargetDto } from './dto/update-validation-target.dto';
import { CreateValidationRuleDto } from './dto/create-validation-rule.dto';
import { ValidationTargetEntity, ValidationRuleEntity, ValidationResultEntity } from './entities/validation-target.entity';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ValidationTargetsService {
  private readonly targetsFile = path.join(process.cwd(), '..', 'data', 'validation-targets.json');
  private readonly rulesFile = path.join(process.cwd(), '..', 'data', 'validation-rules.json');
  private readonly resultsFile = path.join(process.cwd(), '..', 'data', 'validation-results.json');
  private targets: ValidationTargetEntity[] = [];
  private rules: ValidationRuleEntity[] = [];
  private results: ValidationResultEntity[] = [];

  constructor() {
    this.loadData().catch(err => {
      console.error('Error loading validation data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    await Promise.all([
      this.loadTargets(),
      this.loadRules(),
      this.loadResults(),
    ]);
  }

  private async loadTargets(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.targetsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.targetsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.targets = (Array.isArray(parsed) ? parsed : []).map((t: any) => ({
          ...t,
          createdAt: new Date(t.createdAt),
          updatedAt: new Date(t.updatedAt),
          lastValidationAt: t.lastValidationAt ? new Date(t.lastValidationAt) : undefined,
          nextScheduledRun: t.nextScheduledRun ? new Date(t.nextScheduledRun) : undefined,
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.targets = [];
          await this.saveTargets();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading targets:', error);
      this.targets = [];
    }
  }

  private async loadRules(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.rulesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.rulesFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.rules = (Array.isArray(parsed) ? parsed : []).map((r: any) => ({
          ...r,
          createdAt: new Date(r.createdAt),
          updatedAt: new Date(r.updatedAt),
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.rules = [];
          await this.saveRules();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading rules:', error);
      this.rules = [];
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
      console.error('Error loading results:', error);
      this.results = [];
    }
  }

  private async saveTargets() {
    try {
      await fs.mkdir(path.dirname(this.targetsFile), { recursive: true });
      await fs.writeFile(this.targetsFile, JSON.stringify(this.targets, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving targets:', error);
      throw error;
    }
  }

  private async saveRules() {
    try {
      await fs.mkdir(path.dirname(this.rulesFile), { recursive: true });
      await fs.writeFile(this.rulesFile, JSON.stringify(this.rules, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving rules:', error);
      throw error;
    }
  }

  private async saveResults() {
    try {
      await fs.mkdir(path.dirname(this.resultsFile), { recursive: true });
      await fs.writeFile(this.resultsFile, JSON.stringify(this.results, null, 2), 'utf-8');
    } catch (error) {
      console.error('Error saving results:', error);
      throw error;
    }
  }

  // Targets
  async createTarget(dto: CreateValidationTargetDto): Promise<ValidationTargetEntity> {
    const target: ValidationTargetEntity = {
      id: `target-${Date.now()}`,
      name: dto.name,
      type: dto.type,
      description: dto.description,
      connectionConfig: dto.connectionConfig,
      status: ValidationTargetStatus.UNKNOWN,
      ruleIds: dto.ruleIds || [],
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.targets.push(target);
    await this.saveTargets();
    return target;
  }

  async findAllTargets(): Promise<ValidationTargetEntity[]> {
    return this.targets;
  }

  async findOneTarget(id: string): Promise<ValidationTargetEntity> {
    const target = this.targets.find(t => t.id === id);
    if (!target) {
      throw new NotFoundException(`Validation target with ID "${id}" not found`);
    }
    return target;
  }

  async updateTarget(id: string, dto: UpdateValidationTargetDto): Promise<ValidationTargetEntity> {
    const index = this.targets.findIndex(t => t.id === id);
    if (index === -1) {
      throw new NotFoundException(`Validation target with ID "${id}" not found`);
    }

    this.targets[index] = {
      ...this.targets[index],
      ...dto,
      updatedAt: new Date(),
    };

    await this.saveTargets();
    return this.targets[index];
  }

  async removeTarget(id: string): Promise<void> {
    const index = this.targets.findIndex(t => t.id === id);
    if (index === -1) {
      throw new NotFoundException(`Validation target with ID "${id}" not found`);
    }

    // Remove associated rules
    this.rules = this.rules.filter(r => r.targetId !== id);
    await this.saveRules();

    this.targets.splice(index, 1);
    await this.saveTargets();
  }

  async runValidation(id: string): Promise<{ success: boolean; message: string; results: ValidationResultEntity[] }> {
    const target = await this.findOneTarget(id);
    const targetRules = this.rules.filter(r => r.targetId === id && r.enabled);

    // Simulate validation
    const results: ValidationResultEntity[] = targetRules.map(rule => ({
      id: `result-${Date.now()}-${Math.random()}`,
      targetId: id,
      ruleId: rule.id,
      status: Math.random() > 0.3 ? 'passed' : (Math.random() > 0.5 ? 'failed' : 'warning'),
      message: `Validation ${Math.random() > 0.3 ? 'passed' : 'failed'} for rule ${rule.name}`,
      timestamp: new Date(),
    }));

    this.results.push(...results);
    await this.saveResults();

    target.lastValidationAt = new Date();
    target.status = results.some(r => r.status === 'failed') 
      ? ValidationTargetStatus.ERRORS 
      : results.some(r => r.status === 'warning')
      ? ValidationTargetStatus.WARNINGS
      : ValidationTargetStatus.HEALTHY;
    await this.saveTargets();

    return {
      success: true,
      message: `Validation completed for ${target.name}`,
      results,
    };
  }

  // Rules
  async createRule(dto: CreateValidationRuleDto): Promise<ValidationRuleEntity> {
    const rule: ValidationRuleEntity = {
      id: `rule-${Date.now()}`,
      name: dto.name,
      description: dto.description,
      targetId: dto.targetId,
      severity: dto.severity,
      ruleConfig: dto.ruleConfig,
      checkType: dto.checkType,
      conditions: dto.conditions,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    this.rules.push(rule);
    await this.saveRules();

    // Add rule to target
    const target = await this.findOneTarget(dto.targetId);
    if (!target.ruleIds.includes(rule.id)) {
      target.ruleIds.push(rule.id);
      await this.saveTargets();
    }

    return rule;
  }

  async findRulesByTarget(targetId: string): Promise<ValidationRuleEntity[]> {
    return this.rules.filter(r => r.targetId === targetId);
  }

  async findOneRule(id: string): Promise<ValidationRuleEntity> {
    const rule = this.rules.find(r => r.id === id);
    if (!rule) {
      throw new NotFoundException(`Validation rule with ID "${id}" not found`);
    }
    return rule;
  }

  async updateRule(id: string, dto: Partial<CreateValidationRuleDto>): Promise<ValidationRuleEntity> {
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) {
      throw new NotFoundException(`Validation rule with ID "${id}" not found`);
    }

    this.rules[index] = {
      ...this.rules[index],
      ...dto,
      updatedAt: new Date(),
    };

    await this.saveRules();
    return this.rules[index];
  }

  async removeRule(id: string): Promise<void> {
    const index = this.rules.findIndex(r => r.id === id);
    if (index === -1) {
      throw new NotFoundException(`Validation rule with ID "${id}" not found`);
    }

    const rule = this.rules[index];
    this.rules.splice(index, 1);
    await this.saveRules();

    // Remove from target
    const target = await this.findOneTarget(rule.targetId);
    target.ruleIds = target.ruleIds.filter(rid => rid !== id);
    await this.saveTargets();
  }

  // Results
  async findResultsByTarget(targetId: string): Promise<ValidationResultEntity[]> {
    return this.results.filter(r => r.targetId === targetId).sort((a, b) => 
      b.timestamp.getTime() - a.timestamp.getTime()
    );
  }

  async findResultsByRule(ruleId: string): Promise<ValidationResultEntity[]> {
    return this.results.filter(r => r.ruleId === ruleId).sort((a, b) => 
      b.timestamp.getTime() - a.timestamp.getTime()
    );
  }
}

