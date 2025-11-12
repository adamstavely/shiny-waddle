import { Injectable, Inject, forwardRef } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { UnifiedFinding } from '../../../core/unified-finding-schema';
import { NormalizationEngine, ScannerResult } from '../../../services/normalization-engine';
import { ECSAdapter } from '../../../services/ecs-adapter';
import {
  normalizeToCurrentVersion,
  detectSchemaVersion,
  needsMigration,
  migrateFindings,
  CURRENT_SCHEMA_VERSION,
  getSchemaVersion,
  getAvailableVersions,
  validateSchemaVersion,
} from '../../../core/schema-versioning';
// Import migrations to register them
import '../../../core/schema-migrations';
import {
  EnhancedRiskScorer,
  EnhancedRiskScore,
  RiskAggregation,
} from '../../../services/enhanced-risk-scorer';
import { ApplicationsService } from '../applications/applications.service';
import {
  FindingCorrelationEngine,
  CorrelationResult,
} from '../../../services/finding-correlation-engine';
import {
  AttackPathAnalyzer,
  AttackPathAnalysis,
} from '../../../services/attack-path-analyzer';

@Injectable()
export class UnifiedFindingsService {
  private readonly findingsPath = path.join(process.cwd(), '..', '..', 'unified-findings.json');
  private normalizationEngine: NormalizationEngine;
  private ecsAdapter: ECSAdapter;
  private riskScorer: EnhancedRiskScorer;
  private correlationEngine: FindingCorrelationEngine;
  private attackPathAnalyzer: AttackPathAnalyzer;
  private findings: UnifiedFinding[] = [];

  constructor(
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService
  ) {
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
    this.riskScorer = new EnhancedRiskScorer();
    this.correlationEngine = new FindingCorrelationEngine();
    this.attackPathAnalyzer = new AttackPathAnalyzer();
    this.loadFindings();
  }

  private async loadFindings() {
    try {
      const data = await fs.readFile(this.findingsPath, 'utf-8');
      const parsed = JSON.parse(data);
      
      // Migrate findings to current schema version
      const migrated = migrateFindings(parsed);
      
      this.findings = migrated.map((f: any) => ({
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

  /**
   * Schema versioning methods
   */
  async getSchemaVersionInfo(version?: string) {
    if (version) {
      return getSchemaVersion(version);
    }
    return {
      current: CURRENT_SCHEMA_VERSION,
      available: getAvailableVersions(),
    };
  }

  async detectFindingVersion(finding: any) {
    return {
      version: detectSchemaVersion(finding),
      needsMigration: needsMigration(finding),
    };
  }

  async migrateFinding(finding: any, fromVersion?: string, toVersion?: string) {
    if (fromVersion && toVersion) {
      const { migrateFinding: migrate } = await import('../../../core/schema-versioning');
      return migrate(finding, fromVersion, toVersion);
    }
    return normalizeToCurrentVersion(finding);
  }

  async validateFinding(finding: any, version?: string) {
    return validateSchemaVersion(finding, version);
  }

  /**
   * Risk Scoring & Prioritization methods
   */
  
  /**
   * Calculate enhanced risk score for a finding
   */
  async calculateRiskScore(findingId: string): Promise<EnhancedRiskScore> {
    const finding = await this.getFindingById(findingId);
    if (!finding) {
      throw new Error('Finding not found');
    }
    
    const riskScore = this.riskScorer.calculateRiskScore(finding);
    
    // Update finding with enhanced risk score
    finding.enhancedRiskScore = {
      ...riskScore,
      calculatedAt: riskScore.calculatedAt,
    };
    await this.updateFinding(findingId, { enhancedRiskScore: finding.enhancedRiskScore });
    
    return riskScore;
  }

  /**
   * Calculate risk scores for all findings
   */
  async calculateAllRiskScores(): Promise<EnhancedRiskScore[]> {
    const findings = await this.getAllFindings();
    const riskScores = this.riskScorer.calculateRiskScores(findings);
    
    // Update findings with enhanced risk scores
    for (let i = 0; i < findings.length; i++) {
      const finding = findings[i];
      const riskScore = riskScores[i];
      finding.enhancedRiskScore = {
        ...riskScore,
        calculatedAt: riskScore.calculatedAt,
      };
      await this.updateFinding(finding.id, { enhancedRiskScore: finding.enhancedRiskScore });
    }
    
    return riskScores;
  }

  /**
   * Get prioritized findings
   */
  async getPrioritizedFindings(limit?: number): Promise<Array<{ finding: UnifiedFinding; riskScore: EnhancedRiskScore }>> {
    const findings = await this.getAllFindings();
    const prioritized = this.riskScorer.prioritizeFindings(findings);
    
    if (limit) {
      return prioritized.slice(0, limit);
    }
    
    return prioritized;
  }

  /**
   * Aggregate risk by application
   */
  async aggregateRiskByApplication(applicationId: string): Promise<RiskAggregation> {
    const findings = await this.getAllFindings({ applicationId });
    return this.riskScorer.aggregateByApplication(findings, applicationId);
  }

  /**
   * Aggregate risk by team
   */
  async aggregateRiskByTeam(teamName: string): Promise<RiskAggregation> {
    const findings = await this.getAllFindings();
    
    return this.riskScorer.aggregateByTeam(
      findings,
      teamName,
      async (team: string) => {
        const apps = await this.applicationsService.findByTeam(team);
        return apps.map(app => ({ id: app.id }));
      }
    );
  }

  /**
   * Aggregate risk at organization level
   */
  async aggregateRiskByOrganization(): Promise<RiskAggregation> {
    const findings = await this.getAllFindings();
    return this.riskScorer.aggregateByOrganization(findings);
  }

  /**
   * Get risk trends
   */
  async getRiskTrends(periodDays: number = 30): Promise<Array<{ date: Date; riskScore: number; count: number }>> {
    const findings = await this.getAllFindings();
    return this.riskScorer.getRiskTrends(findings, periodDays);
  }

  /**
   * Correlation & Deduplication methods
   */

  /**
   * Correlate findings across scanners
   */
  async correlateFindings(filters?: {
    source?: string;
    scannerId?: string;
    severity?: string;
    status?: string;
    applicationId?: string;
  }): Promise<CorrelationResult> {
    const findings = await this.getAllFindings(filters);
    return this.correlationEngine.correlate(findings);
  }

  /**
   * Get related findings for a specific finding
   */
  async getRelatedFindings(findingId: string): Promise<{
    finding: UnifiedFinding | null;
    related: UnifiedFinding[];
    groups: any[];
    rootCause: any | null;
    impact: any | null;
  }> {
    const finding = await this.getFindingById(findingId);
    if (!finding) {
      throw new Error('Finding not found');
    }

    const correlation = await this.correlateFindings();
    
    const relatedIds = finding.relatedFindings || [];
    const related = this.findings.filter(f => relatedIds.includes(f.id));

    const groups = correlation.groups.filter(g => g.findings.includes(findingId));
    const rootCause = correlation.rootCauses.get(findingId) || null;
    const impact = correlation.impacts.get(findingId) || null;

    return {
      finding,
      related,
      groups,
      rootCause,
      impact,
    };
  }

  /**
   * Attack Path Analysis methods
   */

  /**
   * Analyze attack paths from findings
   */
  async analyzeAttackPaths(filters?: {
    source?: string;
    scannerId?: string;
    severity?: string;
    status?: string;
    applicationId?: string;
  }): Promise<AttackPathAnalysis> {
    const findings = await this.getAllFindings(filters);
    return this.attackPathAnalyzer.analyze(findings);
  }

  /**
   * Get attack paths for a specific application
   */
  async getApplicationAttackPaths(applicationId: string): Promise<{
    applicationId: string;
    attackSurface: any;
    paths: any[];
    criticalPaths: any[];
  }> {
    const analysis = await this.analyzeAttackPaths({ applicationId });
    const attackSurface = analysis.attackSurfaces.get(applicationId);

    if (!attackSurface) {
      return {
        applicationId,
        attackSurface: null,
        paths: [],
        criticalPaths: [],
      };
    }

    return {
      applicationId,
      attackSurface,
      paths: attackSurface.paths,
      criticalPaths: attackSurface.criticalPaths,
    };
  }

  /**
   * Get prioritized findings based on attack paths
   */
  async getAttackPathPrioritizedFindings(limit?: number): Promise<Array<{
    finding: UnifiedFinding;
    priority: number;
    inCriticalPath: boolean;
    attackPaths: any[];
  }>> {
    const analysis = await this.analyzeAttackPaths();
    const findings = await this.getAllFindings();

    const prioritized = findings.map(finding => {
      const priority = analysis.prioritization.get(finding.id) || finding.riskScore || 0;
      const inCriticalPath = analysis.criticalPaths.some(path =>
        path.steps.some(step => step.findingId === finding.id)
      );
      const attackPaths = analysis.paths.filter(path =>
        path.steps.some(step => step.findingId === finding.id)
      );

      return {
        finding,
        priority,
        inCriticalPath,
        attackPaths,
      };
    }).sort((a, b) => b.priority - a.priority);

    if (limit) {
      return prioritized.slice(0, limit);
    }

    return prioritized;
  }
}

