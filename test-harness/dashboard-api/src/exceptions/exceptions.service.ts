import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateExceptionDto } from './dto/create-exception.dto';
import { CreateAllowlistDto } from './dto/create-allowlist.dto';

export interface Exception {
  id: string;
  name: string;
  description: string;
  policyId?: string;
  ruleId?: string;
  reason: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  requestedBy: string;
  requestedAt: Date;
  approvedBy?: string;
  approvedAt?: Date;
  expirationDate?: Date;
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface Allowlist {
  id: string;
  name: string;
  description: string;
  type: 'ip' | 'user' | 'resource' | 'pattern';
  values: string[];
  policyIds?: string[];
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class ExceptionsService {
  private readonly logger = new Logger(ExceptionsService.name);
  private readonly exceptionsFile = path.join(process.cwd(), 'data', 'exceptions.json');
  private readonly allowlistsFile = path.join(process.cwd(), 'data', 'allowlists.json');
  private exceptions: Exception[] = [];
  private allowlists: Allowlist[] = [];

  constructor() {
    this.loadData().catch(err => {
      this.logger.error('Error loading exceptions data on startup:', err);
    });
  }

  private async loadData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.exceptionsFile), { recursive: true });
      
      // Load exceptions
      try {
        const exceptionsData = await fs.readFile(this.exceptionsFile, 'utf-8');
        if (exceptionsData && exceptionsData.trim() !== '') {
          const parsed = JSON.parse(exceptionsData);
          this.exceptions = (Array.isArray(parsed) ? parsed : []).map((e: any) => ({
            ...e,
            requestedAt: e.requestedAt ? new Date(e.requestedAt) : new Date(),
            approvedAt: e.approvedAt ? new Date(e.approvedAt) : undefined,
            expirationDate: e.expirationDate ? new Date(e.expirationDate) : undefined,
            createdAt: e.createdAt ? new Date(e.createdAt) : new Date(),
            updatedAt: e.updatedAt ? new Date(e.updatedAt) : new Date(),
          }));
        } else {
          this.exceptions = [];
          await this.saveExceptions();
        }
      } catch (readError: any) {
        if (readError.code === 'ENOENT' || readError instanceof SyntaxError) {
          this.exceptions = [];
          await this.saveExceptions();
        } else {
          throw readError;
        }
      }

      // Load allowlists
      try {
        const allowlistsData = await fs.readFile(this.allowlistsFile, 'utf-8');
        if (allowlistsData && allowlistsData.trim() !== '') {
          const parsed = JSON.parse(allowlistsData);
          this.allowlists = (Array.isArray(parsed) ? parsed : []).map((a: any) => ({
            ...a,
            createdAt: a.createdAt ? new Date(a.createdAt) : new Date(),
            updatedAt: a.updatedAt ? new Date(a.updatedAt) : new Date(),
          }));
        } else {
          this.allowlists = [];
          await this.saveAllowlists();
        }
      } catch (readError: any) {
        if (readError.code === 'ENOENT' || readError instanceof SyntaxError) {
          this.allowlists = [];
          await this.saveAllowlists();
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading exceptions data:', error);
      this.exceptions = [];
      this.allowlists = [];
    }
  }

  private async saveExceptions(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.exceptionsFile), { recursive: true });
      await fs.writeFile(this.exceptionsFile, JSON.stringify(this.exceptions, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving exceptions:', error);
      throw error;
    }
  }

  private async saveAllowlists(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.allowlistsFile), { recursive: true });
      await fs.writeFile(this.allowlistsFile, JSON.stringify(this.allowlists, null, 2), 'utf-8');
    } catch (error) {
      this.logger.error('Error saving allowlists:', error);
      throw error;
    }
  }

  async getExceptions(policyId?: string, status?: string): Promise<Exception[]> {
    await this.loadData();
    let filtered = [...this.exceptions];
    if (policyId) {
      filtered = filtered.filter(e => e.policyId === policyId);
    }
    if (status) {
      filtered = filtered.filter(e => e.status === status);
    }
    return filtered;
  }

  async createException(dto: CreateExceptionDto): Promise<Exception> {
    await this.loadData();
    const exception: Exception = {
      id: uuidv4(),
      ...dto,
      status: 'pending',
      requestedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.exceptions.push(exception);
    await this.saveExceptions();
    return exception;
  }

  async updateException(id: string, dto: Partial<CreateExceptionDto>): Promise<Exception> {
    await this.loadData();
    const index = this.exceptions.findIndex(e => e.id === id);
    if (index === -1) {
      throw new NotFoundException(`Exception with ID ${id} not found`);
    }
    this.exceptions[index] = {
      ...this.exceptions[index],
      ...dto,
      updatedAt: new Date(),
    };
    await this.saveExceptions();
    return this.exceptions[index];
  }

  async deleteException(id: string): Promise<void> {
    await this.loadData();
    const index = this.exceptions.findIndex(e => e.id === id);
    if (index === -1) {
      throw new NotFoundException(`Exception with ID ${id} not found`);
    }
    this.exceptions.splice(index, 1);
    await this.saveExceptions();
  }

  async approveException(id: string, approver: string, notes?: string): Promise<Exception> {
    await this.loadData();
    const index = this.exceptions.findIndex(e => e.id === id);
    if (index === -1) {
      throw new NotFoundException(`Exception with ID ${id} not found`);
    }
    this.exceptions[index] = {
      ...this.exceptions[index],
      status: 'approved',
      approvedBy: approver,
      approvedAt: new Date(),
      notes: notes || this.exceptions[index].notes,
      updatedAt: new Date(),
    };
    await this.saveExceptions();
    return this.exceptions[index];
  }

  async getAllowlists(): Promise<Allowlist[]> {
    await this.loadData();
    return [...this.allowlists];
  }

  async createAllowlist(dto: CreateAllowlistDto): Promise<Allowlist> {
    await this.loadData();
    const allowlist: Allowlist = {
      id: uuidv4(),
      ...dto,
      enabled: dto.enabled !== undefined ? dto.enabled : true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.allowlists.push(allowlist);
    await this.saveAllowlists();
    return allowlist;
  }

  async updateAllowlist(id: string, dto: Partial<CreateAllowlistDto>): Promise<Allowlist> {
    await this.loadData();
    const index = this.allowlists.findIndex(a => a.id === id);
    if (index === -1) {
      throw new NotFoundException(`Allowlist with ID ${id} not found`);
    }
    this.allowlists[index] = {
      ...this.allowlists[index],
      ...dto,
      updatedAt: new Date(),
    };
    await this.saveAllowlists();
    return this.allowlists[index];
  }

  async deleteAllowlist(id: string): Promise<void> {
    await this.loadData();
    const index = this.allowlists.findIndex(a => a.id === id);
    if (index === -1) {
      throw new NotFoundException(`Allowlist with ID ${id} not found`);
    }
    this.allowlists.splice(index, 1);
    await this.saveAllowlists();
  }
}

