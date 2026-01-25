/**
 * Enhanced Risk Scoring & Prioritization Service
 * 
 * Context-aware risk scoring for unified security findings with:
 * - Multi-factor risk assessment
 * - Threat intelligence integration
 * - Temporal trend analysis
 * - ML-based prioritization
 * - Risk aggregation at multiple levels
 */

import { UnifiedFinding } from '../core/unified-finding-schema';

/**
 * Enhanced Risk Score interface matching ASPM roadmap requirements
 */
export interface EnhancedRiskScore {
  findingId: string;
  baseScore: number; // From CVSS or scanner
  adjustedScore: number; // After context adjustment
  
  factors: {
    severity: number;
    exploitability: number;
    assetCriticality: number;
    exposure: number; // Public-facing, internal-only, etc.
    dataSensitivity: number;
    complianceImpact: number;
    businessImpact: number;
    remediationComplexity: number;
  };
  
  // Temporal factors
  age: number; // How long has this been open? (in days)
  trend: 'increasing' | 'stable' | 'decreasing';
  
  // Threat intelligence
  threatIntelligence?: {
    activeExploits: boolean;
    exploitInWild: boolean;
    ransomware: boolean;
    threatActorInterest: 'high' | 'medium' | 'low';
  };
  
  // Prioritization
  priority: number; // 0-100, higher = more urgent
  priorityReason: string;
  
  // Metadata
  calculatedAt: Date;
  version: string;
}

/**
 * Risk aggregation results
 */
export interface RiskAggregation {
  level: 'application' | 'team' | 'organization';
  identifier: string; // applicationId, team name, or 'organization'
  totalFindings: number;
  riskScore: number; // Aggregated risk score (0-100)
  averageRiskScore: number;
  maxRiskScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  
  // Trend data
  trend: {
    current: number;
    previous: number; // Previous period
    change: number; // Percentage change
    direction: 'increasing' | 'stable' | 'decreasing';
  };
  
  // Breakdown by severity
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  
  // Top risks
  topRisks: Array<{
    findingId: string;
    riskScore: number;
    title: string;
  }>;
}

/**
 * Prioritization configuration
 */
export interface PrioritizationConfig {
  // Weights for different factors
  weights: {
    severity: number;
    exploitability: number;
    assetCriticality: number;
    exposure: number;
    dataSensitivity: number;
    complianceImpact: number;
    businessImpact: number;
    remediationComplexity: number;
    age: number; // How much age affects priority
    threatIntelligence: number;
  };
  
  // SLA-based prioritization thresholds (in days)
  slaThresholds: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  
  // ML model configuration (placeholder for future ML integration)
  mlConfig?: {
    enabled: boolean;
    modelVersion?: string;
    confidenceThreshold?: number;
  };
}

/**
 * Asset criticality mapping
 */
export interface AssetCriticalityConfig {
  // Application-level criticality
  applications: Record<string, 'critical' | 'high' | 'medium' | 'low'>;
  
  // Component-level criticality patterns
  componentPatterns: Array<{
    pattern: RegExp;
    criticality: 'critical' | 'high' | 'medium' | 'low';
  }>;
  
  // Default criticality based on asset type
  defaultByType: Record<string, 'critical' | 'high' | 'medium' | 'low'>;
}

/**
 * Enhanced Risk Scorer
 */
export class EnhancedRiskScorer {
  private config: PrioritizationConfig;
  private assetCriticality: AssetCriticalityConfig;
  private historicalScores: Map<string, EnhancedRiskScore[]> = new Map(); // For trend analysis

  constructor(
    config?: Partial<PrioritizationConfig>,
    assetCriticality?: Partial<AssetCriticalityConfig>
  ) {
    this.config = {
      weights: {
        severity: 0.20,
        exploitability: 0.15,
        assetCriticality: 0.15,
        exposure: 0.10,
        dataSensitivity: 0.10,
        complianceImpact: 0.10,
        businessImpact: 0.10,
        remediationComplexity: -0.05, // Negative: easier remediation = higher priority
        age: 0.05,
        threatIntelligence: 0.10,
      },
      slaThresholds: {
        critical: 1, // 1 day
        high: 7, // 7 days
        medium: 30, // 30 days
        low: 90, // 90 days
      },
      ...config,
    };

    this.assetCriticality = {
      applications: {},
      componentPatterns: [
        { pattern: /auth|login|session/i, criticality: 'critical' },
        { pattern: /payment|billing|transaction/i, criticality: 'critical' },
        { pattern: /user|profile|account/i, criticality: 'high' },
        { pattern: /api\/v1\/admin/i, criticality: 'critical' },
        { pattern: /api\/public/i, criticality: 'high' },
      ],
      defaultByType: {
        application: 'high',
        infrastructure: 'medium',
        dependency: 'medium',
        container: 'high',
        iac: 'medium',
        api: 'high',
      },
      ...assetCriticality,
    };
  }

  /**
   * Calculate enhanced risk score for a finding
   */
  calculateRiskScore(finding: UnifiedFinding): EnhancedRiskScore {
    const baseScore = this.extractBaseScore(finding);
    const factors = this.calculateFactors(finding);
    const age = this.calculateAge(finding);
    const trend = this.calculateTrend(finding);
    const threatIntelligence = this.assessThreatIntelligence(finding);
    
    // Calculate adjusted score
    const adjustedScore = this.adjustScore(baseScore, factors, age, threatIntelligence);
    
    // Calculate priority
    const { priority, reason } = this.calculatePriority(
      finding,
      factors,
      adjustedScore,
      age,
      threatIntelligence
    );

    const riskScore: EnhancedRiskScore = {
      findingId: finding.id,
      baseScore,
      adjustedScore,
      factors,
      age,
      trend,
      threatIntelligence,
      priority,
      priorityReason: reason,
      calculatedAt: new Date(),
      version: '1.0.0',
    };

    // Store for trend analysis
    this.storeHistoricalScore(finding.id, riskScore);

    return riskScore;
  }

  /**
   * Calculate risk scores for multiple findings
   */
  calculateRiskScores(findings: UnifiedFinding[]): EnhancedRiskScore[] {
    return findings.map(finding => this.calculateRiskScore(finding));
  }

  /**
   * Prioritize findings using ML-based and business context
   */
  prioritizeFindings(
    findings: UnifiedFinding[],
    riskScores?: EnhancedRiskScore[]
  ): Array<{ finding: UnifiedFinding; riskScore: EnhancedRiskScore }> {
    const scores = riskScores || this.calculateRiskScores(findings);
    
    // Combine findings with scores
    const combined = findings.map(finding => ({
      finding,
      riskScore: scores.find(s => s.findingId === finding.id)!,
    }));

    // Sort by priority (descending)
    return combined.sort((a, b) => {
      // First by priority score
      if (b.riskScore.priority !== a.riskScore.priority) {
        return b.riskScore.priority - a.riskScore.priority;
      }
      
      // Then by adjusted score
      if (b.riskScore.adjustedScore !== a.riskScore.adjustedScore) {
        return b.riskScore.adjustedScore - a.riskScore.adjustedScore;
      }
      
      // Then by severity
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return severityOrder[b.finding.severity] - severityOrder[a.finding.severity];
    });
  }

  /**
   * Aggregate risk scores by application
   */
  aggregateByApplication(
    findings: UnifiedFinding[],
    applicationId: string
  ): RiskAggregation {
    const appFindings = findings.filter(
      f => f.asset.applicationId === applicationId
    );
    return this.aggregateRisks(appFindings, 'application', applicationId);
  }

  /**
   * Aggregate risk scores by team
   */
  async aggregateByTeam(
    findings: UnifiedFinding[],
    teamName: string,
    getApplicationsByTeam: (team: string) => Promise<Array<{ id: string }>>
  ): Promise<RiskAggregation> {
    const applications = await getApplicationsByTeam(teamName);
    const appIds = new Set(applications.map(app => app.id));
    const teamFindings = findings.filter(
      f => f.asset.applicationId && appIds.has(f.asset.applicationId)
    );
    return this.aggregateRisks(teamFindings, 'team', teamName);
  }

  /**
   * Aggregate risk scores at organization level
   */
  aggregateByOrganization(findings: UnifiedFinding[]): RiskAggregation {
    return this.aggregateRisks(findings, 'organization', 'organization');
  }

  /**
   * Get risk trends over time
   */
  getRiskTrends(
    findings: UnifiedFinding[],
    periodDays: number = 30
  ): Array<{ date: Date; riskScore: number; count: number }> {
    const now = new Date();
    const periodStart = new Date(now.getTime() - periodDays * 24 * 60 * 60 * 1000);
    
    const trends: Array<{ date: Date; riskScore: number; count: number }> = [];
    const dailyScores: Map<string, { total: number; count: number }> = new Map();

    for (const finding of findings) {
      if (finding.createdAt < periodStart) continue;
      
      const dateKey = finding.createdAt.toISOString().split('T')[0];
      const riskScore = this.calculateRiskScore(finding);
      
      const existing = dailyScores.get(dateKey) || { total: 0, count: 0 };
      existing.total += riskScore.adjustedScore;
      existing.count += 1;
      dailyScores.set(dateKey, existing);
    }

    for (const [dateKey, data] of dailyScores.entries()) {
      trends.push({
        date: new Date(dateKey),
        riskScore: data.count > 0 ? data.total / data.count : 0,
        count: data.count,
      });
    }

    return trends.sort((a, b) => a.date.getTime() - b.date.getTime());
  }

  /**
   * Extract base score from finding (CVSS or scanner score)
   */
  private extractBaseScore(finding: UnifiedFinding): number {
    // Try CVSS score first
    if (finding.vulnerability?.cve?.score?.base) {
      return finding.vulnerability.cve.score.base * 10; // Convert 0-10 to 0-100
    }
    
    // Use existing riskScore if available
    if (finding.riskScore !== undefined) {
      return finding.riskScore;
    }
    
    // Fallback to severity mapping
    const severityScores: Record<string, number> = {
      critical: 90,
      high: 70,
      medium: 50,
      low: 30,
      info: 10,
    };
    
    return severityScores[finding.severity] || 50;
  }

  /**
   * Calculate all risk factors
   */
  private calculateFactors(finding: UnifiedFinding): EnhancedRiskScore['factors'] {
    return {
      severity: this.calculateSeverityFactor(finding),
      exploitability: this.calculateExploitabilityFactor(finding),
      assetCriticality: this.calculateAssetCriticalityFactor(finding),
      exposure: this.calculateExposureFactor(finding),
      dataSensitivity: this.calculateDataSensitivityFactor(finding),
      complianceImpact: this.calculateComplianceImpactFactor(finding),
      businessImpact: this.calculateBusinessImpactFactor(finding),
      remediationComplexity: this.calculateRemediationComplexityFactor(finding),
    };
  }

  /**
   * Calculate severity factor (0-100)
   */
  private calculateSeverityFactor(finding: UnifiedFinding): number {
    const severityScores: Record<string, number> = {
      critical: 100,
      high: 75,
      medium: 50,
      low: 25,
      info: 10,
    };
    return severityScores[finding.severity] || 50;
  }

  /**
   * Calculate exploitability factor (0-100)
   */
  private calculateExploitabilityFactor(finding: UnifiedFinding): number {
    // Check if CVSS has exploitability metrics
    if (finding.vulnerability?.cve?.score?.vector) {
      const vector = finding.vulnerability.cve.score.vector;
      // Parse CVSS vector for exploitability (AV, AC, PR, UI, S)
      // Simplified: check for network access and low complexity
      if (vector.includes('AV:N') && vector.includes('AC:L')) {
        return 90; // Network accessible, low complexity = high exploitability
      }
      if (vector.includes('AV:N')) {
        return 70; // Network accessible
      }
      if (vector.includes('AV:L')) {
        return 50; // Local access required
      }
    }
    
    // Check confidence level
    if (finding.confidence === 'confirmed') {
      return 80; // Confirmed findings are more exploitable
    }
    
    // Default based on severity
    const severityExploitability: Record<string, number> = {
      critical: 85,
      high: 70,
      medium: 50,
      low: 30,
      info: 10,
    };
    
    return severityExploitability[finding.severity] || 50;
  }

  /**
   * Calculate asset criticality factor (0-100)
   */
  private calculateAssetCriticalityFactor(finding: UnifiedFinding): number {
    const appId = finding.asset.applicationId;
    
    // Check application-level criticality
    if (appId && this.assetCriticality.applications[appId]) {
      const crit = this.assetCriticality.applications[appId];
      const criticalityScores: Record<string, number> = {
        critical: 100,
        high: 75,
        medium: 50,
        low: 25,
      };
      return criticalityScores[crit];
    }
    
    // Check component patterns
    const component = finding.asset.component || '';
    const location = finding.asset.location;
    const fullPath = location?.file?.path || location?.url?.path || component;
    
    for (const pattern of this.assetCriticality.componentPatterns) {
      if (pattern.pattern.test(fullPath)) {
        const criticalityScores: Record<string, number> = {
          critical: 100,
          high: 75,
          medium: 50,
          low: 25,
        };
        return criticalityScores[pattern.criticality];
      }
    }
    
    // Default by asset type
    const defaultCrit = this.assetCriticality.defaultByType[finding.asset.type] || 'medium';
    const criticalityScores: Record<string, number> = {
      critical: 100,
      high: 75,
      medium: 50,
      low: 25,
    };
    return criticalityScores[defaultCrit];
  }

  /**
   * Calculate exposure factor (0-100)
   */
  private calculateExposureFactor(finding: UnifiedFinding): number {
    const location = finding.asset.location;
    
    // Check if it's a public-facing endpoint
    if (location?.url) {
      const url = location.url;
      // Public endpoints (no auth required typically)
      if (url.path?.includes('/public') || url.path?.includes('/api/public')) {
        return 90;
      }
      // Admin endpoints
      if (url.path?.includes('/admin') || url.path?.includes('/api/admin')) {
        return 70; // Admin endpoints are exposed but require auth
      }
      // Internal endpoints
      if (url.path?.includes('/internal') || url.path?.includes('/api/internal')) {
        return 40;
      }
      // Default for API endpoints
      return 60;
    }
    
    // Check if it's infrastructure (cloud resources)
    if (finding.asset.type === 'infrastructure' || finding.asset.type === 'iac') {
      const resource = location?.resource || '';
      // Public cloud resources
      if (resource.includes('s3') || resource.includes('bucket')) {
        return 80; // S3 buckets often public
      }
      if (resource.includes('public') || resource.includes('external')) {
        return 70;
      }
      return 50; // Default for infrastructure
    }
    
    // Container images
    if (finding.asset.type === 'container') {
      return 60; // Containers can be deployed publicly
    }
    
    // Default: internal exposure
    return 40;
  }

  /**
   * Calculate data sensitivity factor (0-100)
   */
  private calculateDataSensitivityFactor(finding: UnifiedFinding): number {
    // Check compliance frameworks (indicates sensitive data)
    if (finding.compliance?.frameworks) {
      const sensitiveFrameworks = ['HIPAA', 'PCI-DSS', 'GDPR'];
      const hasSensitive = finding.compliance.frameworks.some(f => 
        sensitiveFrameworks.includes(f)
      );
      if (hasSensitive) {
        return 90;
      }
    }
    
    // Check if PII-related
    const title = finding.title.toLowerCase();
    const description = finding.description.toLowerCase();
    const piiKeywords = ['pii', 'ssn', 'credit card', 'password', 'secret', 'token', 'api key'];
    if (piiKeywords.some(keyword => title.includes(keyword) || description.includes(keyword))) {
      return 85;
    }
    
    // Check vulnerability classification
    if (finding.vulnerability?.classification) {
      const classification = finding.vulnerability.classification.toLowerCase();
      if (classification.includes('cwe-359') || classification.includes('privacy')) {
        return 80;
      }
    }
    
    // Default based on severity
    const severitySensitivity: Record<string, number> = {
      critical: 70,
      high: 60,
      medium: 40,
      low: 20,
      info: 10,
    };
    
    return severitySensitivity[finding.severity] || 40;
  }

  /**
   * Calculate compliance impact factor (0-100)
   */
  private calculateComplianceImpactFactor(finding: UnifiedFinding): number {
    if (!finding.compliance?.frameworks || finding.compliance.frameworks.length === 0) {
      return 0;
    }
    
    // Each framework adds impact
    let impact = 0;
    const frameworkWeights: Record<string, number> = {
      'SOC 2': 20,
      'PCI-DSS': 30,
      'HIPAA': 30,
      'GDPR': 25,
      'ISO 27001': 20,
      'NIST': 25,
    };
    
    for (const framework of finding.compliance.frameworks) {
      impact += frameworkWeights[framework] || 15;
    }
    
    // Check if it's a control violation
    if (finding.compliance.controls && finding.compliance.controls.length > 0) {
      impact += 10 * finding.compliance.controls.length;
    }
    
    return Math.min(100, impact);
  }

  /**
   * Calculate business impact factor (0-100)
   */
  private calculateBusinessImpactFactor(finding: UnifiedFinding): number {
    // Use existing businessImpact if available
    if (finding.businessImpact !== undefined) {
      return finding.businessImpact;
    }
    
    // Calculate based on asset criticality and exposure
    const assetCrit = this.calculateAssetCriticalityFactor(finding);
    const exposure = this.calculateExposureFactor(finding);
    const dataSensitivity = this.calculateDataSensitivityFactor(finding);
    
    // Weighted combination
    return (assetCrit * 0.4) + (exposure * 0.3) + (dataSensitivity * 0.3);
  }

  /**
   * Calculate remediation complexity factor (0-100, higher = more complex = lower priority)
   */
  private calculateRemediationComplexityFactor(finding: UnifiedFinding): number {
    const remediation = finding.remediation;
    
    // Check if automated remediation is available
    if (remediation.automated) {
      return 20; // Low complexity
    }
    
    // Estimate based on effort
    if (remediation.estimatedEffort) {
      const effortScores: Record<string, number> = {
        low: 30,
        medium: 60,
        high: 90,
      };
      return effortScores[remediation.estimatedEffort] || 50;
    }
    
    // Estimate based on number of steps
    const stepCount = remediation.steps?.length || 0;
    if (stepCount === 0) {
      return 50; // Unknown complexity
    }
    if (stepCount <= 2) {
      return 30; // Simple
    }
    if (stepCount <= 5) {
      return 60; // Moderate
    }
    return 90; // Complex
  }

  /**
   * Calculate age of finding in days
   */
  private calculateAge(finding: UnifiedFinding): number {
    const detectedDate = finding.detectedAt || finding.createdAt;
    const now = new Date();
    const diffTime = now.getTime() - detectedDate.getTime();
    return Math.floor(diffTime / (1000 * 60 * 60 * 24));
  }

  /**
   * Calculate trend (increasing, stable, decreasing)
   */
  private calculateTrend(finding: UnifiedFinding): 'increasing' | 'stable' | 'decreasing' {
    const historical = this.historicalScores.get(finding.id) || [];
    if (historical.length < 2) {
      return 'stable';
    }
    
    // Compare last two scores
    const recent = historical.slice(-2);
    const change = recent[1].adjustedScore - recent[0].adjustedScore;
    
    if (change > 5) {
      return 'increasing';
    } else if (change < -5) {
      return 'decreasing';
    }
    return 'stable';
  }

  /**
   * Assess threat intelligence
   */
  private assessThreatIntelligence(finding: UnifiedFinding): EnhancedRiskScore['threatIntelligence'] {
    // This would integrate with threat intelligence feeds
    // For now, use heuristics based on vulnerability data
    
    const cveId = finding.vulnerability?.cve?.id || finding.vulnerability?.id;
    if (!cveId) {
      return undefined;
    }
    
    // Check if it's a known exploited vulnerability (simplified)
    const title = finding.title.toLowerCase();
    const description = finding.description.toLowerCase();
    
    const hasActiveExploit = 
      title.includes('exploit') ||
      title.includes('active') ||
      description.includes('exploit in the wild');
    
    const hasRansomware = 
      title.includes('ransomware') ||
      description.includes('ransomware');
    
    // Determine threat actor interest based on severity and type
    let threatActorInterest: 'high' | 'medium' | 'low' = 'low';
    if (finding.severity === 'critical' || finding.severity === 'high') {
      if (hasActiveExploit || hasRansomware) {
        threatActorInterest = 'high';
      } else {
        threatActorInterest = 'medium';
      }
    }
    
    return {
      activeExploits: hasActiveExploit,
      exploitInWild: hasActiveExploit,
      ransomware: hasRansomware,
      threatActorInterest,
    };
  }

  /**
   * Adjust base score with factors
   */
  private adjustScore(
    baseScore: number,
    factors: EnhancedRiskScore['factors'],
    age: number,
    threatIntelligence?: EnhancedRiskScore['threatIntelligence']
  ): number {
    let adjusted = baseScore;
    
    // Apply factor adjustments
    const weights = this.config.weights;
    adjusted += (factors.severity - 50) * weights.severity;
    adjusted += (factors.exploitability - 50) * weights.exploitability;
    adjusted += (factors.assetCriticality - 50) * weights.assetCriticality;
    adjusted += (factors.exposure - 50) * weights.exposure;
    adjusted += (factors.dataSensitivity - 50) * weights.dataSensitivity;
    adjusted += factors.complianceImpact * weights.complianceImpact;
    adjusted += factors.businessImpact * weights.businessImpact;
    adjusted -= factors.remediationComplexity * Math.abs(weights.remediationComplexity);
    
    // Age adjustment (older findings get slight boost if critical)
    if (age > this.config.slaThresholds.critical && baseScore > 70) {
      adjusted += age * 0.1; // Slight increase for overdue critical issues
    }
    
    // Threat intelligence adjustment
    if (threatIntelligence) {
      if (threatIntelligence.activeExploits || threatIntelligence.exploitInWild) {
        adjusted += 15;
      }
      if (threatIntelligence.ransomware) {
        adjusted += 20;
      }
      if (threatIntelligence.threatActorInterest === 'high') {
        adjusted += 10;
      }
    }
    
    // Clamp to 0-100
    return Math.max(0, Math.min(100, adjusted));
  }

  /**
   * Calculate priority with business context
   */
  private calculatePriority(
    finding: UnifiedFinding,
    factors: EnhancedRiskScore['factors'],
    adjustedScore: number,
    age: number,
    threatIntelligence?: EnhancedRiskScore['threatIntelligence']
  ): { priority: number; reason: string } {
    let priority = adjustedScore;
    const reasons: string[] = [];
    
    // SLA-based prioritization
    const severity = finding.severity;
    const slaThreshold = this.config.slaThresholds[severity] || 30;
    if (age > slaThreshold) {
      const overdueDays = age - slaThreshold;
      priority += Math.min(20, overdueDays * 2); // Boost for overdue items
      reasons.push(`Overdue by ${overdueDays} days (SLA: ${slaThreshold} days)`);
    }
    
    // Threat intelligence boost
    if (threatIntelligence?.activeExploits || threatIntelligence?.exploitInWild) {
      priority += 25;
      reasons.push('Active exploit in the wild');
    }
    
    if (threatIntelligence?.ransomware) {
      priority += 30;
      reasons.push('Ransomware threat');
    }
    
    // Business impact boost
    if (factors.businessImpact > 70) {
      priority += 10;
      reasons.push('High business impact');
    }
    
    // Compliance impact boost
    if (factors.complianceImpact > 50) {
      priority += 10;
      reasons.push('Compliance violation');
    }
    
    // Remediation complexity (easier = higher priority)
    if (factors.remediationComplexity < 30) {
      priority += 5;
      reasons.push('Easy to remediate');
    }
    
    // Clamp to 0-100
    priority = Math.max(0, Math.min(100, priority));
    
    const reason = reasons.length > 0 
      ? reasons.join('; ')
      : `Risk score: ${adjustedScore.toFixed(1)}`;
    
    return { priority, reason };
  }

  /**
   * Aggregate risks at a given level
   */
  private aggregateRisks(
    findings: UnifiedFinding[],
    level: 'application' | 'team' | 'organization',
    identifier: string
  ): RiskAggregation {
    const riskScores = this.calculateRiskScores(findings);
    
    if (riskScores.length === 0) {
      return {
        level,
        identifier,
        totalFindings: 0,
        riskScore: 0,
        averageRiskScore: 0,
        maxRiskScore: 0,
        criticalCount: 0,
        highCount: 0,
        mediumCount: 0,
        lowCount: 0,
        trend: {
          current: 0,
          previous: 0,
          change: 0,
          direction: 'stable',
        },
        bySeverity: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
        },
        topRisks: [],
      };
    }
    
    // Calculate aggregated metrics
    const totalScore = riskScores.reduce((sum, rs) => sum + rs.adjustedScore, 0);
    const averageScore = totalScore / riskScores.length;
    const maxScore = Math.max(...riskScores.map(rs => rs.adjustedScore));
    
    // Count by severity
    const bySeverity = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    
    for (const finding of findings) {
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    }
    
    // Calculate aggregated risk score (weighted average)
    const aggregatedScore = this.calculateAggregatedRiskScore(riskScores);
    
    // Get top risks
    const topRisks = riskScores
      .sort((a, b) => b.adjustedScore - a.adjustedScore)
      .slice(0, 10)
      .map(rs => {
        const finding = findings.find(f => f.id === rs.findingId)!;
        return {
          findingId: rs.findingId,
          riskScore: rs.adjustedScore,
          title: finding.title,
        };
      });
    
    // Calculate trend (simplified - compare current vs previous period)
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const recentFindings = findings.filter(f => f.createdAt >= thirtyDaysAgo);
    const olderFindings = findings.filter(f => f.createdAt < thirtyDaysAgo);
    
    const currentScore = recentFindings.length > 0
      ? recentFindings.reduce((sum, f) => {
          const rs = riskScores.find(s => s.findingId === f.id);
          return sum + (rs?.adjustedScore || 0);
        }, 0) / recentFindings.length
      : 0;
    
    const previousScore = olderFindings.length > 0
      ? olderFindings.reduce((sum, f) => {
          const rs = riskScores.find(s => s.findingId === f.id);
          return sum + (rs?.adjustedScore || 0);
        }, 0) / olderFindings.length
      : 0;
    
    const change = previousScore > 0 
      ? ((currentScore - previousScore) / previousScore) * 100 
      : 0;
    
    return {
      level,
      identifier,
      totalFindings: findings.length,
      riskScore: aggregatedScore,
      averageRiskScore: averageScore,
      maxRiskScore: maxScore,
      criticalCount: bySeverity.critical,
      highCount: bySeverity.high,
      mediumCount: bySeverity.medium,
      lowCount: bySeverity.low,
      trend: {
        current: currentScore,
        previous: previousScore,
        change,
        direction: change > 5 ? 'increasing' : change < -5 ? 'decreasing' : 'stable',
      },
      bySeverity,
      topRisks,
    };
  }

  /**
   * Calculate aggregated risk score (weighted by severity)
   */
  private calculateAggregatedRiskScore(riskScores: EnhancedRiskScore[]): number {
    if (riskScores.length === 0) return 0;
    
    // Weight by severity
    const severityWeights: Record<string, number> = {
      critical: 1.0,
      high: 0.75,
      medium: 0.5,
      low: 0.25,
      info: 0.1,
    };
    
    let weightedSum = 0;
    let totalWeight = 0;
    
    for (const rs of riskScores) {
      // Find the finding to get severity
      // For now, use a simplified approach
      const weight = 1.0; // Could be enhanced to use actual severity
      weightedSum += rs.adjustedScore * weight;
      totalWeight += weight;
    }
    
    return totalWeight > 0 ? weightedSum / totalWeight : 0;
  }

  /**
   * Store historical score for trend analysis
   */
  private storeHistoricalScore(findingId: string, score: EnhancedRiskScore): void {
    const historical = this.historicalScores.get(findingId) || [];
    historical.push(score);
    
    // Keep only last 30 scores
    if (historical.length > 30) {
      historical.shift();
    }
    
    this.historicalScores.set(findingId, historical);
  }

  /**
   * Update asset criticality configuration
   */
  updateAssetCriticality(config: Partial<AssetCriticalityConfig>): void {
    this.assetCriticality = {
      ...this.assetCriticality,
      ...config,
      applications: {
        ...this.assetCriticality.applications,
        ...config.applications,
      },
      componentPatterns: [
        ...this.assetCriticality.componentPatterns,
        ...(config.componentPatterns || []),
      ],
    };
  }

  /**
   * Update prioritization configuration
   */
  updateConfig(config: Partial<PrioritizationConfig>): void {
    this.config = {
      ...this.config,
      ...config,
      weights: {
        ...this.config.weights,
        ...config.weights,
      },
    };
  }
}

