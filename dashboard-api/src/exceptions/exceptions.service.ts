import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateExceptionDto } from './dto/create-exception.dto';

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

@Injectable()
export class ExceptionsService {
  private readonly logger = new Logger(ExceptionsService.name);
  private readonly exceptionsFile = path.join(process.cwd(), 'data', 'exceptions.json');
  private exceptions: Exception[] = [];

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
          try {
            await this.saveExceptions();
          } catch (saveError) {
            // Ignore save errors - data is already set to empty array
            this.logger.warn('Failed to save exceptions file, continuing with empty array:', saveError);
          }
        }
      } catch (readError: any) {
        if (readError.code === 'ENOENT' || readError instanceof SyntaxError) {
          this.exceptions = [];
          try {
            await this.saveExceptions();
          } catch (saveError) {
            // Ignore save errors - data is already set to empty array
            this.logger.warn('Failed to save exceptions file, continuing with empty array:', saveError);
          }
        } else {
          throw readError;
        }
      }
    } catch (error) {
      this.logger.error('Error loading exceptions data:', error);
      this.exceptions = [];
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
}

