import { Injectable, NotFoundException, BadRequestException, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { TestBatteryEntity } from './entities/test-battery.entity';
import { CreateTestBatteryDto } from './dto/create-test-battery.dto';
import { UpdateTestBatteryDto } from './dto/update-test-battery.dto';

@Injectable()
export class TestBatteriesService {
  private readonly logger = new Logger(TestBatteriesService.name);
  private readonly batteriesFile = path.join(process.cwd(), 'data', 'test-batteries.json');
  private batteries: TestBatteryEntity[] = [];

  constructor() {
    this.loadBatteries().catch(err => {
      this.logger.error('Error loading test batteries on startup:', err);
    });
  }

  private async loadBatteries(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.batteriesFile), { recursive: true });
      try {
        const data = await fs.readFile(this.batteriesFile, 'utf-8');
        if (!data || data.trim() === '') {
          this.batteries = [];
          await this.saveBatteries();
          return;
        }
        const parsed = JSON.parse(data);
        if (!Array.isArray(parsed)) {
          this.logger.warn('Test batteries file does not contain an array, initializing empty');
          this.batteries = [];
          await this.saveBatteries();
          return;
        }
        this.batteries = parsed.map((b: any) => ({
          ...b,
          createdAt: b.createdAt ? new Date(b.createdAt) : new Date(),
          updatedAt: b.updatedAt ? new Date(b.updatedAt) : new Date(),
          harnessIds: b.harnessIds || [],
        }));
      } catch (readError: any) {
        if (readError.code === 'ENOENT') {
          this.batteries = [];
          await this.saveBatteries();
        } else if (readError instanceof SyntaxError) {
          this.logger.error('JSON parsing error in test batteries file, initializing empty:', readError.message);
          this.batteries = [];
          await this.saveBatteries();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading test batteries:', error);
      this.batteries = [];
    }
  }

  private async saveBatteries(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.batteriesFile), { recursive: true });
      await fs.writeFile(this.batteriesFile, JSON.stringify(this.batteries, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving test batteries:', error);
      throw error;
    }
  }

  async create(dto: CreateTestBatteryDto): Promise<TestBatteryEntity> {
    await this.loadBatteries();

    // Check for duplicate name
    const existing = this.batteries.find(b => b.name === dto.name);
    if (existing) {
      throw new BadRequestException(`Test battery with name "${dto.name}" already exists`);
    }

    const now = new Date();
    const battery: TestBatteryEntity = {
      id: uuidv4(),
      name: dto.name,
      description: dto.description,
      harnessIds: dto.harnessIds || [],
      executionConfig: dto.executionConfig,
      team: dto.team,
      createdAt: now,
      updatedAt: now,
    };

    this.batteries.push(battery);
    await this.saveBatteries();

    this.logger.log(`Created test battery: ${battery.id} (${battery.name})`);
    return battery;
  }

  async findAll(): Promise<TestBatteryEntity[]> {
    await this.loadBatteries();
    return [...this.batteries];
  }

  async findOne(id: string): Promise<TestBatteryEntity> {
    await this.loadBatteries();
    const battery = this.batteries.find(b => b.id === id);
    if (!battery) {
      throw new NotFoundException(`Test battery with ID "${id}" not found`);
    }
    return battery;
  }

  async update(id: string, dto: UpdateTestBatteryDto): Promise<TestBatteryEntity> {
    await this.loadBatteries();
    const index = this.batteries.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test battery with ID "${id}" not found`);
    }

    // Check for duplicate name if name is being updated
    if (dto.name && dto.name !== this.batteries[index].name) {
      const existing = this.batteries.find(b => b.name === dto.name && b.id !== id);
      if (existing) {
        throw new BadRequestException(`Test battery with name "${dto.name}" already exists`);
      }
    }

    const updated: TestBatteryEntity = {
      ...this.batteries[index],
      ...dto,
      updatedAt: new Date(),
    };

    this.batteries[index] = updated;
    await this.saveBatteries();

    this.logger.log(`Updated test battery: ${id}`);
    return updated;
  }

  async delete(id: string): Promise<void> {
    await this.loadBatteries();
    const index = this.batteries.findIndex(b => b.id === id);
    if (index === -1) {
      throw new NotFoundException(`Test battery with ID "${id}" not found`);
    }

    this.batteries.splice(index, 1);
    await this.saveBatteries();

    this.logger.log(`Deleted test battery: ${id}`);
  }

  async addHarness(batteryId: string, harnessId: string): Promise<TestBatteryEntity> {
    await this.loadBatteries();
    const battery = await this.findOne(batteryId);
    
    if (!battery.harnessIds.includes(harnessId)) {
      battery.harnessIds.push(harnessId);
      battery.updatedAt = new Date();
      await this.saveBatteries();
      this.logger.log(`Added harness ${harnessId} to battery ${batteryId}`);
    }

    return battery;
  }

  async removeHarness(batteryId: string, harnessId: string): Promise<TestBatteryEntity> {
    await this.loadBatteries();
    const battery = await this.findOne(batteryId);
    
    const index = battery.harnessIds.indexOf(harnessId);
    if (index > -1) {
      battery.harnessIds.splice(index, 1);
      battery.updatedAt = new Date();
      await this.saveBatteries();
      this.logger.log(`Removed harness ${harnessId} from battery ${batteryId}`);
    }

    return battery;
  }
}

