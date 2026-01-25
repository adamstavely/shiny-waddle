import { Injectable, Inject, forwardRef, Logger } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { UnifiedFinding } from '../../heimdall-framework/core/unified-finding-schema';
import { NormalizationEngine, ScannerResult } from '../../heimdall-framework/services/normalization-engine';
import { ECSAdapter } from '../../heimdall-framework/services/ecs-adapter';
import {
  normalizeToCurrentVersion,
  detectSchemaVersion,
  needsMigration,
  migrateFindings,
  CURRENT_SCHEMA_VERSION,
  getSchemaVersion,
  getAvailableVersions,
  validateSchemaVersion,
} from '../../heimdall-framework/core/schema-versioning';
// Import migrations to register them
import '../../../core/schema-migrations';
import {
  EnhancedRiskScorer,
  EnhancedRiskScore,
  RiskAggregation,
} from '../../heimdall-framework/services/enhanced-risk-scorer';
import { ApplicationsService } from '../applications/applications.service';
import {
  FindingCorrelationEngine,
  CorrelationResult,
} from '../../heimdall-framework/services/finding-correlation-engine';
import {
  AttackPathAnalyzer,
  AttackPathAnalysis,
} from '../../heimdall-framework/services/attack-path-analyzer';
import { NotificationsService } from '../notifications/notifications.service';
import { UsersService } from '../users/users.service';
import { AlertingService } from '../alerting/alerting.service';

@Injectable()
export class UnifiedFindingsService {
  private readonly logger = new Logger(UnifiedFindingsService.name);
  private readonly findingsPath = path.join(process.cwd(), '..', '..', 'unified-findings.json');
  private readonly complianceScoresHistoryPath = path.join(process.cwd(), '..', 'data', 'compliance-scores-history.json');
  private normalizationEngine: NormalizationEngine;
  private ecsAdapter: ECSAdapter;
  private riskScorer: EnhancedRiskScorer;
  private correlationEngine: FindingCorrelationEngine;
  private attackPathAnalyzer: AttackPathAnalyzer;
  private findings: UnifiedFinding[] = [];

  constructor(
    @Inject(forwardRef(() => ApplicationsService))
    private readonly applicationsService: ApplicationsService,
    @Inject(forwardRef(() => AlertingService))
    private readonly alertingService?: AlertingService,
    @Inject(forwardRef(() => NotificationsService))
    private readonly notificationsService: NotificationsService,
    @Inject(forwardRef(() => UsersService))
    private readonly usersService: UsersService
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
      this.logger.error('Failed to save findings:', error);
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
      const isNew = existingIndex < 0;
      
      if (existingIndex >= 0) {
        this.findings[existingIndex] = finding;
      } else {
        this.findings.push(finding);
      }

      // Notify about new critical findings
      if (isNew && finding.severity === 'critical' && this.notificationsService) {
        try {
          const userIds = await this.getUsersToNotify(
            finding.asset.applicationId ? [finding.asset.applicationId] : undefined
          );
          for (const userId of userIds) {
            await this.notificationsService.notifyCriticalFinding(
              userId,
              finding.id,
              finding.title
            );
          }
        } catch (err) {
          this.logger.error('Failed to notify about critical finding:', err);
          // Don't throw - notification failures shouldn't break ingestion
        }
      }

      // Evaluate alert rules for new findings
      if (isNew && this.alertingService) {
        try {
          await this.alertingService.evaluateFinding(finding);
        } catch (err) {
          this.logger.error('Failed to evaluate alert rules for finding:', err);
          // Don't throw - alert evaluation failures shouldn't break ingestion
        }
      }
    }

    await this.saveFindings();
    
    // Store compliance score after new findings
    this.storeComplianceScoreAfterUpdate().catch(err => {
      this.logger.error('Failed to store compliance score after ingestion:', err);
    });
    
    return normalized;
  }

  async updateFinding(id: string, updates: Partial<UnifiedFinding>): Promise<UnifiedFinding> {
    const index = this.findings.findIndex(f => f.id === id);
    if (index === -1) {
      throw new Error('Finding not found');
    }

    const currentFinding = this.findings[index];

    // Block direct status changes to 'risk-accepted' or 'false-positive'
    // These require approval workflow
    if (updates.status === 'risk-accepted' || updates.status === 'false-positive') {
      if (currentFinding.status !== updates.status) {
        throw new Error(
          `Cannot directly change status to '${updates.status}'. Please create an approval request first.`
        );
      }
    }

    const updatedFinding = {
      ...currentFinding,
      ...updates,
      updatedAt: new Date(),
    };
    this.findings[index] = updatedFinding;

    await this.saveFindings();

    // Evaluate alert rules if severity or status changed
    if (this.alertingService && (updates.severity || updates.status)) {
      try {
        await this.alertingService.evaluateFinding(updatedFinding);
      } catch (err) {
        this.logger.error('Failed to evaluate alert rules for updated finding:', err);
        // Don't throw - alert evaluation failures shouldn't break updates
      }
    }

    // Store compliance score after update (async, don't wait)
    this.storeComplianceScoreAfterUpdate().catch(err => {
      this.logger.error('Failed to store compliance score after update:', err);
    });

    return this.findings[index];
  }

  /**
   * Store compliance score after finding update
   */
  private async storeComplianceScoreAfterUpdate(): Promise<void> {
    try {
      // Store overall score
      const overallScore = this.calculateComplianceScore(this.findings);
      const history = await this.loadComplianceScoreHistory();
      const previousScore = history.length > 0 ? history[history.length - 1].score : overallScore;
      
      await this.storeComplianceScore(overallScore);

      // Check for score drop and notify
      if (this.notificationsService && overallScore < previousScore) {
        const scoreChange = overallScore - previousScore;
        
        // Get users to notify (all users, since this is overall score)
        const userIds = await this.getUsersToNotify();
        
        for (const userId of userIds) {
          try {
            // Check each user's preferences individually
            const preferences = this.notificationsService.getUserPreferences(userId);
            
            // Only notify if drop exceeds this user's threshold
            if (Math.abs(scoreChange) >= preferences.scoreDropThreshold) {
              await this.notificationsService.notifyScoreDrop(
                userId,
                scoreChange,
                previousScore,
                overallScore
              );
            }
          } catch (err) {
            this.logger.error(`Failed to notify user ${userId} about score drop:`, err);
            // Don't throw - notification failures shouldn't break finding updates
          }
        }
      }

      // Store per-application scores
      const appGroups = new Map<string, UnifiedFinding[]>();
      this.findings.forEach(f => {
        if (f.asset.applicationId) {
          if (!appGroups.has(f.asset.applicationId)) {
            appGroups.set(f.asset.applicationId, []);
          }
          appGroups.get(f.asset.applicationId)!.push(f);
        }
      });

      for (const [appId, appFindings] of appGroups.entries()) {
        const appScore = this.calculateComplianceScore(appFindings);
        await this.storeComplianceScore(appScore, [appId]);
        
        // Check for application-specific score drops
        const appHistory = await this.loadComplianceScoreHistory();
        const appPreviousScore = appHistory
          .filter(h => h.applicationIds.includes(appId))
          .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())[0]?.score;
        
        if (appPreviousScore !== undefined && appScore < appPreviousScore) {
          const appScoreChange = appScore - appPreviousScore;
          
          // Get users associated with this application
          const userIds = await this.getUsersToNotify([appId]);
          
          for (const userId of userIds) {
            try {
              // Check each user's preferences individually
              const preferences = this.notificationsService.getUserPreferences(userId);
              
              // Only notify if drop exceeds this user's threshold
              if (Math.abs(appScoreChange) >= preferences.scoreDropThreshold) {
                await this.notificationsService.notifyScoreDrop(
                  userId,
                  appScoreChange,
                  appPreviousScore,
                  appScore,
                  appId
                );
              }
            } catch (err) {
              this.logger.error(`Failed to notify user ${userId} about app score drop:`, err);
              // Don't throw - notification failures shouldn't break finding updates
            }
          }
        }
      }
    } catch (error) {
      this.logger.error('Error in storeComplianceScoreAfterUpdate:', error);
      // Don't throw - score tracking failures shouldn't break finding updates
    }
  }

  /**
   * Get users to notify for score drops
   * Returns user IDs associated with the given applications/teams
   */
  private async getUsersToNotify(applicationIds?: string[], teamNames?: string[]): Promise<string[]> {
    try {
      const users = await this.usersService.getUsersByApplicationsAndTeams(applicationIds, teamNames);
      
      if (users.length === 0) {
        this.logger.warn(
          `No users found for applications: ${applicationIds?.join(', ') || 'none'}, teams: ${teamNames?.join(', ') || 'none'}`
        );
        return [];
      }

      return users.map(u => u.id);
    } catch (error) {
      this.logger.error('Error getting users to notify:', error);
      // Return empty array on error - don't break notification flow
      return [];
    }
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

  /**
   * Developer Dashboard methods
   */

  /**
   * Calculate compliance score based on findings
   * Score = (resolved + risk-accepted) / total * 100
   */
  calculateComplianceScore(findings: UnifiedFinding[]): number {
    if (findings.length === 0) return 100;

    const resolvedCount = findings.filter(f => 
      f.status === 'resolved' || f.status === 'risk-accepted'
    ).length;

    return Math.round((resolvedCount / findings.length) * 100);
  }

  /**
   * Get developer dashboard data
   */
  async getDeveloperDashboard(applicationIds?: string[], teamNames?: string[]): Promise<{
    currentScore: number;
    previousScore: number;
    trend: 'up' | 'down' | 'stable';
    scoreChange: number;
    findings: {
      total: number;
      bySeverity: Record<string, number>;
      byStatus: Record<string, number>;
    };
    trends: Array<{
      date: string;
      score: number;
    }>;
    recentFindings: UnifiedFinding[];
  }> {
    // Filter findings by application/team
    let filteredFindings = [...this.findings];

    if (applicationIds && applicationIds.length > 0) {
      filteredFindings = filteredFindings.filter(f => 
        f.asset.applicationId && applicationIds.includes(f.asset.applicationId)
      );
    }

    if (teamNames && teamNames.length > 0) {
      // Get applications for these teams
      const teamApplications = await Promise.all(
        teamNames.map(team => this.applicationsService.findByTeam(team))
      );
      const teamAppIds = new Set(
        teamApplications.flat().map(app => app.id)
      );
      filteredFindings = filteredFindings.filter(f =>
        f.asset.applicationId && teamAppIds.has(f.asset.applicationId)
      );
    }

    // Calculate current score
    const currentScore = this.calculateComplianceScore(filteredFindings);

    // Get historical scores
    const history = await this.loadComplianceScoreHistory();
    const previousScore = history.length > 0 
      ? history[history.length - 1].score 
      : currentScore;

    // Calculate trend
    const scoreChange = currentScore - previousScore;
    let trend: 'up' | 'down' | 'stable' = 'stable';
    if (scoreChange > 0) trend = 'up';
    else if (scoreChange < 0) trend = 'down';

    // Get findings breakdown
    const bySeverity: Record<string, number> = {};
    const byStatus: Record<string, number> = {};

    filteredFindings.forEach(f => {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byStatus[f.status] = (byStatus[f.status] || 0) + 1;
    });

    // Get trends (last 30 days)
    const trends = await this.getComplianceTrends(30, applicationIds, teamNames);

    // Get recent findings (last 10)
    const recentFindings = filteredFindings
      .sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime())
      .slice(0, 10);

    return {
      currentScore,
      previousScore,
      trend,
      scoreChange,
      findings: {
        total: filteredFindings.length,
        bySeverity,
        byStatus,
      },
      trends,
      recentFindings,
    };
  }

  /**
   * Store compliance score in history
   */
  async storeComplianceScore(
    score: number,
    applicationIds?: string[],
    teamNames?: string[]
  ): Promise<void> {
    const history = await this.loadComplianceScoreHistory();
    
    history.push({
      date: new Date().toISOString(),
      score,
      applicationIds: applicationIds || [],
      teamNames: teamNames || [],
    });

    // Keep only last 365 days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 365);
    const filtered = history.filter(h => new Date(h.date) >= cutoffDate);

    await this.saveComplianceScoreHistory(filtered);
  }

  /**
   * Get compliance trends over time
   */
  async getComplianceTrends(
    days: number = 30,
    applicationIds?: string[],
    teamNames?: string[]
  ): Promise<Array<{ date: string; score: number }>> {
    const history = await this.loadComplianceScoreHistory();
    
    // Filter by application/team if provided
    let filtered = history;
    if (applicationIds && applicationIds.length > 0) {
      filtered = filtered.filter(h => 
        h.applicationIds.length === 0 || 
        h.applicationIds.some(id => applicationIds.includes(id))
      );
    }
    if (teamNames && teamNames.length > 0) {
      filtered = filtered.filter(h =>
        h.teamNames.length === 0 ||
        h.teamNames.some(name => teamNames.includes(name))
      );
    }

    // Get last N days
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);
    filtered = filtered.filter(h => new Date(h.date) >= cutoffDate);

    // Group by date and average scores for same date
    const byDate = new Map<string, number[]>();
    filtered.forEach(h => {
      const dateKey = h.date.split('T')[0]; // YYYY-MM-DD
      if (!byDate.has(dateKey)) {
        byDate.set(dateKey, []);
      }
      byDate.get(dateKey)!.push(h.score);
    });

    // Calculate average per day
    const trends = Array.from(byDate.entries())
      .map(([date, scores]) => ({
        date,
        score: Math.round(scores.reduce((a, b) => a + b, 0) / scores.length),
      }))
      .sort((a, b) => a.date.localeCompare(b.date));

    return trends;
  }

  /**
   * Load compliance score history
   */
  private async loadComplianceScoreHistory(): Promise<Array<{
    date: string;
    score: number;
    applicationIds: string[];
    teamNames: string[];
  }>> {
    try {
      await fs.mkdir(path.dirname(this.complianceScoresHistoryPath), { recursive: true });
      try {
        const data = await fs.readFile(this.complianceScoresHistoryPath, 'utf-8');
        if (!data || data.trim() === '') {
          return [];
        }
        return JSON.parse(data);
      } catch {
        return [];
      }
    } catch {
      return [];
    }
  }

  /**
   * Save compliance score history
   */
  private async saveComplianceScoreHistory(
    history: Array<{
      date: string;
      score: number;
      applicationIds: string[];
      teamNames: string[];
    }>
  ): Promise<void> {
    try {
      await fs.mkdir(path.dirname(this.complianceScoresHistoryPath), { recursive: true });
      await fs.writeFile(
        this.complianceScoresHistoryPath,
        JSON.stringify(history, null, 2),
        'utf-8'
      );
    } catch (error) {
      this.logger.error('Failed to save compliance score history:', error);
    }
  }

  /**
   * Get remediation help for a finding
   */
  async getRemediationHelp(findingId: string): Promise<{
    finding: UnifiedFinding;
    remediationSteps: string[];
    references: string[];
    estimatedEffort?: string;
    automated?: boolean;
    knowledgeBaseArticles?: Array<{
      title: string;
      url: string;
      description: string;
    }>;
    similarFindings?: Array<{
      id: string;
      title: string;
      status: string;
      resolutionDate?: Date;
    }>;
  }> {
    const finding = await this.getFindingById(findingId);
    if (!finding) {
      throw new Error('Finding not found');
    }

    // Load knowledge base
    const knowledgeBasePath = path.join(process.cwd(), '..', 'data', 'remediation-knowledge-base.json');
    let knowledgeBase: Record<string, any> = {};
    try {
      const kbData = await fs.readFile(knowledgeBasePath, 'utf-8');
      knowledgeBase = JSON.parse(kbData);
    } catch {
      // Knowledge base doesn't exist yet, use defaults
    }

    // Find relevant knowledge base articles
    const articles: Array<{ title: string; url: string; description: string }> = [];
    if (finding.vulnerability?.cve?.id && knowledgeBase[finding.vulnerability.cve.id]) {
      articles.push(...knowledgeBase[finding.vulnerability.cve.id]);
    }
    if (finding.vulnerability?.classification && knowledgeBase[finding.vulnerability.classification]) {
      articles.push(...knowledgeBase[finding.vulnerability.classification]);
    }
    if (finding.source && knowledgeBase[finding.source]) {
      articles.push(...knowledgeBase[finding.source]);
    }

    // Find similar findings (same CVE or classification)
    const similarFindings = this.findings
      .filter(f => 
        f.id !== findingId &&
        (
          (finding.vulnerability?.cve?.id && f.vulnerability?.cve?.id === finding.vulnerability.cve.id) ||
          (finding.vulnerability?.classification && f.vulnerability?.classification === finding.vulnerability.classification)
        ) &&
        (f.status === 'resolved' || f.status === 'risk-accepted')
      )
      .slice(0, 5)
      .map(f => ({
        id: f.id,
        title: f.title,
        status: f.status,
        resolutionDate: f.resolvedAt,
      }));

    return {
      finding,
      remediationSteps: finding.remediation.steps,
      references: finding.remediation.references,
      estimatedEffort: finding.remediation.estimatedEffort,
      automated: finding.remediation.automated,
      knowledgeBaseArticles: articles,
      similarFindings,
    };
  }
}

