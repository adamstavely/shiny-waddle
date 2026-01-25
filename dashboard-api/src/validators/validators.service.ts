import { Injectable, NotFoundException, ConflictException, OnModuleInit, Logger } from '@nestjs/common';
import { CreateValidatorDto, ValidatorStatus } from './dto/create-validator.dto';
import { UpdateValidatorDto } from './dto/update-validator.dto';
import { ValidatorEntity } from './entities/validator.entity';
import { ValidatorDiscoveryService } from './validator-discovery.service';
import * as fs from 'fs/promises';
import * as path from 'path';

@Injectable()
export class ValidatorsService implements OnModuleInit {
  private readonly logger = new Logger(ValidatorsService.name);
  private readonly validatorsFile = path.join(process.cwd(), '..', 'data', 'validators.json');
  private validators: ValidatorEntity[] = [];

  constructor(private readonly discoveryService: ValidatorDiscoveryService) {}

  async onModuleInit() {
    // Load existing validators from file first
    await this.loadValidators();
    // Auto-discover validators from framework on module initialization
    await this.discoverAndRegisterValidators();
  }

  /**
   * Discover validators from framework and register them if they don't exist
   */
  async discoverAndRegisterValidators(): Promise<{ message: string; discovered: number }> {
    try {
      const discoveredValidators = await this.discoveryService.discoverValidators();
      
      for (const discovered of discoveredValidators) {
        // Check if validator already exists
        const existing = this.validators.find(v => v.id === discovered.id);
        
        if (!existing) {
          // Add discovered validator
          this.validators.push(discovered);
          this.logger.log(`Auto-registered validator: ${discovered.name} (${discovered.id})`);
        } else {
          // Update metadata if version changed
          if (existing.version !== discovered.version) {
            existing.version = discovered.version;
            existing.description = discovered.description;
            existing.metadata = discovered.metadata;
            existing.updatedAt = new Date();
            this.logger.log(`Updated validator metadata: ${discovered.name} (${discovered.id})`);
          }
        }
      }

      // Save updated validators list
      if (discoveredValidators.length > 0) {
        await this.saveValidators();
      }

      const newCount = discoveredValidators.filter(d => 
        !this.validators.find(v => v.id === d.id)
      ).length;

      return {
        message: `Discovered ${discoveredValidators.length} validators, ${newCount} new`,
        discovered: newCount,
      };
    } catch (error: any) {
      this.logger.error(`Error discovering validators: ${error.message}`, error.stack);
      throw error;
    }
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
      this.logger.error('Error loading validators:', error);
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
      this.logger.error('Error saving validators:', error);
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

