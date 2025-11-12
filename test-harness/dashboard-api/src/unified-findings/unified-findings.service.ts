import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { UnifiedFinding } from '../../../core/unified-finding-schema';
import { NormalizationEngine, ScannerResult } from '../../../services/normalization-engine';
import { ECSAdapter } from '../../../services/ecs-adapter';

@Injectable()
export class UnifiedFindingsService {
  private readonly findingsPath = path.join(process.cwd(), '..', '..', 'unified-findings.json');
  private normalizationEngine: NormalizationEngine;
  private ecsAdapter: ECSAdapter;
  private findings: UnifiedFinding[] = [];

  constructor() {
    this.normalizationEngine = new NormalizationEngine({
      deduplication: {
        enabled: true,
        strategy: 'fuzzy',
        similarityThreshold: 0.8,
      },
      enrichment: {
        enabled: true,
        enrichCVE: true,
        enrichCWE: true,
        enrichCompliance: true,
      },
      validation: {
        enabled: true,
        strictMode: false,
      },
    });
    this.ecsAdapter = new ECSAdapter();
    this.loadFindings();
  }

  private async loadFindings() {
    try {
      const data = await fs.readFile(this.findingsPath, 'utf-8');
      const parsed = JSON.parse(data);
      this.findings = parsed.map((f: any) => ({
        ...f,
        createdAt: new Date(f.createdAt),
        updatedAt: new Date(f.updatedAt),
        resolvedAt: f.resolvedAt ? new Date(f.resolvedAt) : undefined,
        detectedAt: f.detectedAt ? new Date(f.detectedAt) : undefined,
      }));
    } catch (error) {
      // File doesn't exist, start with empty array
      this.findings = [];
    }
  }

  private async saveFindings() {
    try {
      await fs.writeFile(
        this.findingsPath,
        JSON.stringify(this.findings, null, 2),
        'utf-8'
      );
    } catch (error) {
      console.error('Failed to save findings:', error);
    }
  }

  async getAllFindings(filters?: {
    source?: string;
    scannerId?: string;
    severity?: string;
    status?: string;
    applicationId?: string;
  }): Promise<UnifiedFinding[]> {
    let filtered = [...this.findings];

    if (filters) {
      if (filters.source) {
        filtered = filtered.filter(f => f.source === filters.source);
      }
      if (filters.scannerId) {
        filtered = filtered.filter(f => f.scannerId === filters.scannerId);
      }
      if (filters.severity) {
        filtered = filtered.filter(f => f.severity === filters.severity);
      }
      if (filters.status) {
        filtered = filtered.filter(f => f.status === filters.status);
      }
      if (filters.applicationId) {
        filtered = filtered.filter(f => f.asset.applicationId === filters.applicationId);
      }
    }

    return filtered.sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async getFindingById(id: string): Promise<UnifiedFinding | null> {
    return this.findings.find(f => f.id === id) || null;
  }

  async normalizeAndIngest(scannerResults: ScannerResult[]): Promise<UnifiedFinding[]> {
    const normalized = await this.normalizationEngine.normalize(scannerResults);
    
    // Merge with existing findings (deduplication handled by engine)
    for (const finding of normalized) {
      const existingIndex = this.findings.findIndex(f => f.id === finding.id);
      if (existingIndex >= 0) {
        this.findings[existingIndex] = finding;
      } else {
        this.findings.push(finding);
      }
    }

    await this.saveFindings();
    return normalized;
  }

  async updateFinding(id: string, updates: Partial<UnifiedFinding>): Promise<UnifiedFinding> {
    const index = this.findings.findIndex(f => f.id === id);
    if (index === -1) {
      throw new Error('Finding not found');
    }

    this.findings[index] = {
      ...this.findings[index],
      ...updates,
      updatedAt: new Date(),
    };

    await this.saveFindings();
    return this.findings[index];
  }

  async deleteFinding(id: string): Promise<void> {
    const index = this.findings.findIndex(f => f.id === id);
    if (index === -1) {
      throw new Error('Finding not found');
    }

    this.findings.splice(index, 1);
    await this.saveFindings();
  }

  async getFindingsAsECS(filters?: any): Promise<any[]> {
    const findings = await this.getAllFindings(filters);
    return this.ecsAdapter.batchToECS(findings);
  }

  async getStatistics(): Promise<{
    total: number;
    bySource: Record<string, number>;
    bySeverity: Record<string, number>;
    byStatus: Record<string, number>;
    byScanner: Record<string, number>;
  }> {
    const stats = {
      total: this.findings.length,
      bySource: {} as Record<string, number>,
      bySeverity: {} as Record<string, number>,
      byStatus: {} as Record<string, number>,
      byScanner: {} as Record<string, number>,
    };

    for (const finding of this.findings) {
      stats.bySource[finding.source] = (stats.bySource[finding.source] || 0) + 1;
      stats.bySeverity[finding.severity] = (stats.bySeverity[finding.severity] || 0) + 1;
      stats.byStatus[finding.status] = (stats.byStatus[finding.status] || 0) + 1;
      stats.byScanner[finding.scannerId] = (stats.byScanner[finding.scannerId] || 0) + 1;
    }

    return stats;
  }
}

