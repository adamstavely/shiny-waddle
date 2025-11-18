import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { v4 as uuidv4 } from 'uuid';
import { CreateMappingDto } from './dto/create-mapping.dto';

export interface ComplianceStandard {
  id: string;
  name: string;
  version: string;
  description: string;
  framework: 'nist' | 'soc2' | 'iso27001' | 'pci-dss' | 'hipaa' | 'gdpr';
}

export interface PolicyMapping {
  id: string;
  standardId: string;
  policyId: string;
  controlId: string;
  controlName: string;
  mappingType: 'direct' | 'partial' | 'related';
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

@Injectable()
export class StandardsMappingService {
  private readonly logger = new Logger(StandardsMappingService.name);
  private readonly dataFile = path.join(process.cwd(), 'data', 'standards-mappings.json');
  private standards: ComplianceStandard[] = [];
  private mappings: PolicyMapping[] = [];

  constructor() {
    this.loadData().catch(err => {
      this.logger.error('Error loading standards mapping data on startup:', err);
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
        this.standards = parsed.standards || [];
        this.mappings = (parsed.mappings || []).map((m: any) => ({
          ...m,
          createdAt: m.createdAt ? new Date(m.createdAt) : new Date(),
          updatedAt: m.updatedAt ? new Date(m.updatedAt) : new Date(),
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
      this.logger.error('Error loading standards mapping data:', error);
      this.initializeDefaults();
    }
  }

  private initializeDefaults(): void {
    this.standards = [
      { id: 'nist-800-53', name: 'NIST 800-53', version: 'Rev 5', description: 'NIST Security and Privacy Controls', framework: 'nist' },
      { id: 'soc2', name: 'SOC 2', version: 'Type II', description: 'Service Organization Control 2', framework: 'soc2' },
      { id: 'iso-27001', name: 'ISO 27001', version: '2022', description: 'Information Security Management', framework: 'iso27001' },
      { id: 'pci-dss', name: 'PCI DSS', version: '4.0', description: 'Payment Card Industry Data Security Standard', framework: 'pci-dss' },
      { id: 'hipaa', name: 'HIPAA', version: '2023', description: 'Health Insurance Portability and Accountability Act', framework: 'hipaa' },
      { id: 'gdpr', name: 'GDPR', version: '2018', description: 'General Data Protection Regulation', framework: 'gdpr' },
    ];
    this.mappings = [];
  }

  private async saveData(): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.dataFile), { recursive: true });
      await fs.writeFile(
        this.dataFile,
        JSON.stringify({ standards: this.standards, mappings: this.mappings }, null, 2),
        'utf-8',
      );
    } catch (error) {
      this.logger.error('Error saving standards mapping data:', error);
      throw error;
    }
  }

  async getStandards(): Promise<ComplianceStandard[]> {
    await this.loadData();
    return [...this.standards];
  }

  async getMappings(standardId: string): Promise<PolicyMapping[]> {
    await this.loadData();
    return this.mappings.filter(m => m.standardId === standardId);
  }

  async createMapping(standardId: string, dto: CreateMappingDto): Promise<PolicyMapping> {
    await this.loadData();
    // Verify standard exists
    if (!this.standards.find(s => s.id === standardId)) {
      throw new NotFoundException(`Standard with ID ${standardId} not found`);
    }
    const mapping: PolicyMapping = {
      id: uuidv4(),
      standardId,
      ...dto,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    this.mappings.push(mapping);
    await this.saveData();
    return mapping;
  }

  async deleteMapping(standardId: string, mappingId: string): Promise<void> {
    await this.loadData();
    const index = this.mappings.findIndex(m => m.id === mappingId && m.standardId === standardId);
    if (index === -1) {
      throw new NotFoundException(`Mapping with ID ${mappingId} not found for standard ${standardId}`);
    }
    this.mappings.splice(index, 1);
    await this.saveData();
  }

  async getStandardsForPolicy(policyId: string): Promise<Array<{ standard: ComplianceStandard; mappings: PolicyMapping[] }>> {
    await this.loadData();
    const policyMappings = this.mappings.filter(m => m.policyId === policyId);
    const standardsMap = new Map<string, ComplianceStandard>();
    this.standards.forEach(s => standardsMap.set(s.id, s));
    
    const result: Array<{ standard: ComplianceStandard; mappings: PolicyMapping[] }> = [];
    const standardsUsed = new Set<string>();
    
    policyMappings.forEach(mapping => {
      if (!standardsUsed.has(mapping.standardId)) {
        standardsUsed.add(mapping.standardId);
        const standard = standardsMap.get(mapping.standardId);
        if (standard) {
          result.push({
            standard,
            mappings: policyMappings.filter(m => m.standardId === mapping.standardId),
          });
        }
      }
    });
    
    return result;
  }
}

