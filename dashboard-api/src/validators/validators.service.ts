import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { CreateValidatorDto, ValidatorStatus } from './dto/create-validator.dto';
import { UpdateValidatorDto } from './dto/update-validator.dto';
import { ValidatorEntity } from './entities/validator.entity';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ValidatorsService {
  private readonly validatorsFile = path.join(process.cwd(), '..', 'data', 'validators.json');
  private validators: ValidatorEntity[] = [];

  constructor() {
    this.loadValidators().catch(err => {
      console.error('Error loading validators on startup:', err);
    });
  }

  private async loadValidators(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.validatorsFile), { recursive: true });
      try {
        const data = await fs.readFile(this.validatorsFile, 'utf-8');
        const parsed = JSON.parse(data);
        this.validators = (Array.isArray(parsed) ? parsed : []).map((v: any) => ({
          ...v,
          registeredAt: new Date(v.registeredAt),
          lastRunAt: v.lastRunAt ? new Date(v.lastRunAt) : undefined,
          updatedAt: new Date(v.updatedAt),
          enabled: v.enabled !== undefined ? v.enabled : true,
          testCount: v.testCount || 0,
          successCount: v.successCount || 0,
          failureCount: v.failureCount || 0,
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.validators = [];
          await this.saveValidators();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      console.error('Error loading validators:', error);
      this.validators = [];
    }
  }

  private async saveValidators() {
    try {
      await fs.mkdir(path.dirname(this.validatorsFile), { recursive: true });
      await fs.writeFile(
        this.validatorsFile,
        JSON.stringify(this.validators, null, 2),
        'utf-8',
      );
    } catch (error) {
      console.error('Error saving validators:', error);
      throw error;
    }
  }

  async create(createValidatorDto: CreateValidatorDto): Promise<ValidatorEntity> {
    const existing = this.validators.find(v => v.id === createValidatorDto.id);
    if (existing) {
      throw new ConflictException(`Validator with ID "${createValidatorDto.id}" already exists`);
    }

    const validator: ValidatorEntity = {
      id: createValidatorDto.id,
      name: createValidatorDto.name,
      description: createValidatorDto.description,
      testType: createValidatorDto.testType,
      version: createValidatorDto.version,
      metadata: createValidatorDto.metadata,
      config: createValidatorDto.config || {},
      enabled: createValidatorDto.enabled !== undefined ? createValidatorDto.enabled : true,
      registeredAt: new Date(),
      testCount: 0,
      successCount: 0,
      failureCount: 0,
      updatedAt: new Date(),
    };

    this.validators.push(validator);
    await this.saveValidators();

    return validator;
  }

  async findAll(): Promise<ValidatorEntity[]> {
    return this.validators;
  }

  async findOne(id: string): Promise<ValidatorEntity> {
    const validator = this.validators.find(v => v.id === id);
    if (!validator) {
      throw new NotFoundException(`Validator with ID "${id}" not found`);
    }
    return validator;
  }

  async update(id: string, updateValidatorDto: UpdateValidatorDto): Promise<ValidatorEntity> {
    const index = this.validators.findIndex(v => v.id === id);
    if (index === -1) {
      throw new NotFoundException(`Validator with ID "${id}" not found`);
    }

    this.validators[index] = {
      ...this.validators[index],
      ...updateValidatorDto,
      updatedAt: new Date(),
    };

    await this.saveValidators();

    return this.validators[index];
  }

  async remove(id: string): Promise<void> {
    const index = this.validators.findIndex(v => v.id === id);
    if (index === -1) {
      throw new NotFoundException(`Validator with ID "${id}" not found`);
    }

    this.validators.splice(index, 1);
    await this.saveValidators();
  }

  async enable(id: string): Promise<ValidatorEntity> {
    const validator = await this.findOne(id);
    validator.enabled = true;
    validator.updatedAt = new Date();
    await this.saveValidators();
    return validator;
  }

  async disable(id: string): Promise<ValidatorEntity> {
    const validator = await this.findOne(id);
    validator.enabled = false;
    validator.updatedAt = new Date();
    await this.saveValidators();
    return validator;
  }

  async testConnection(id: string): Promise<{ success: boolean; message: string }> {
    const validator = await this.findOne(id);
    
    // Simulate connection test
    // In a real implementation, this would actually test the validator's connection
    return {
      success: true,
      message: `Connection test successful for ${validator.name}`,
    };
  }

  async findByType(testType: string): Promise<ValidatorEntity[]> {
    return this.validators.filter(v => v.testType === testType);
  }

  async findEnabled(): Promise<ValidatorEntity[]> {
    return this.validators.filter(v => v.enabled);
  }
}

