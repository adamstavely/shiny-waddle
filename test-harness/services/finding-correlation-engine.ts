/**
 * Finding Correlation Engine
 * 
 * Provides intelligent correlation and deduplication of findings across multiple scanners.
 * Handles cross-scanner deduplication, related finding grouping, root cause analysis,
 * and impact analysis.
 */

import { UnifiedFinding } from '../core/unified-finding-schema';

export interface CorrelationConfig {
  enabled: boolean;
  crossScannerDeduplication: {
    enabled: boolean;
    similarityThreshold: number; // 0-1, default 0.85
    strategies: ('cve' | 'cwe' | 'location' | 'semantic' | 'asset')[];
  };
  relatedFindingGrouping: {
    enabled: boolean;
    maxDistance: number; // Maximum "distance" for related findings
    groupingStrategies: ('cwe-chain' | 'asset-chain' | 'dependency-chain' | 'attack-path')[];
  };
  rootCauseAnalysis: {
    enabled: boolean;
    maxDepth: number; // Maximum depth for root cause analysis
  };
  impactAnalysis: {
    enabled: boolean;
    considerAssetCriticality: boolean;
    considerBusinessImpact: boolean;
  };
}

export interface RelatedFindingGroup {
  id: string;
  primaryFinding: string; // ID of the primary finding
  findings: string[]; // All finding IDs in the group
  relationshipType: 'duplicate' | 'related' | 'chain' | 'cluster';
  confidence: number; // 0-1
  rootCause?: string; // ID of the root cause finding
  impactScore: number; // 0-100
  createdAt: Date;
}

export interface RootCauseAnalysis {
  findingId: string;
  rootCause?: string; // ID of the root cause finding
  chain: string[]; // Chain of finding IDs leading to root cause
  depth: number;
  confidence: number; // 0-1
  analysis: {
    type: 'dependency' | 'configuration' | 'code' | 'infrastructure' | 'unknown';
    description: string;
    evidence: string[];
  };
}

export interface ImpactAnalysis {
  findingId: string;
  directImpact: {
    affectedAssets: string[];
    affectedApplications: string[];
    severity: 'critical' | 'high' | 'medium' | 'low';
    businessImpact: number; // 0-100
  };
  cascadingImpact: {
    relatedFindings: string[];
    potentialExploits: string[];
    complianceImpact: string[]; // Affected compliance frameworks
    estimatedRemediationCost: number;
  };
  overallImpactScore: number; // 0-100
}

export interface CorrelationResult {
  findings: UnifiedFinding[];
  groups: RelatedFindingGroup[];
  rootCauses: Map<string, RootCauseAnalysis>;
  impacts: Map<string, ImpactAnalysis>;
  duplicates: Map<string, string>; // findingId -> primaryFindingId
  statistics: {
    totalFindings: number;
    uniqueFindings: number;
    duplicateCount: number;
    groupCount: number;
    averageGroupSize: number;
  };
}

export class FindingCorrelationEngine {
  private config: CorrelationConfig;
  private findingsIndex: Map<string, UnifiedFinding>;
  private assetIndex: Map<string, UnifiedFinding[]>; // asset -> findings
  private cveIndex: Map<string, UnifiedFinding[]>; // CVE -> findings
  private cweIndex: Map<string, UnifiedFinding[]>; // CWE -> findings

  constructor(config?: Partial<CorrelationConfig>) {
    this.config = {
      enabled: true,
      crossScannerDeduplication: {
        enabled: true,
        similarityThreshold: 0.85,
        strategies: ['cve', 'cwe', 'location', 'asset'],
        ...config?.crossScannerDeduplication,
      },
      relatedFindingGrouping: {
        enabled: true,
        maxDistance: 3,
        groupingStrategies: ['cwe-chain', 'asset-chain', 'dependency-chain', 'attack-path'],
        ...config?.relatedFindingGrouping,
      },
      rootCauseAnalysis: {
        enabled: true,
        maxDepth: 5,
        ...config?.rootCauseAnalysis,
      },
      impactAnalysis: {
        enabled: true,
        considerAssetCriticality: true,
        considerBusinessImpact: true,
        ...config?.impactAnalysis,
      },
      ...config,
    };

    this.findingsIndex = new Map();
    this.assetIndex = new Map();
    this.cveIndex = new Map();
    this.cweIndex = new Map();
  }

  /**
   * Correlate findings across scanners
   */
  async correlate(findings: UnifiedFinding[]): Promise<CorrelationResult> {
    if (!this.config.enabled) {
      return {
        findings,
        groups: [],
        rootCauses: new Map(),
        impacts: new Map(),
        duplicates: new Map(),
        statistics: {
          totalFindings: findings.length,
          uniqueFindings: findings.length,
          duplicateCount: 0,
          groupCount: 0,
          averageGroupSize: 0,
        },
      };
    }

    // Build indices
    this.buildIndices(findings);

    // Step 1: Cross-scanner deduplication
    let deduplicatedFindings = findings;
    const duplicates = new Map<string, string>();

    if (this.config.crossScannerDeduplication.enabled) {
      const dedupResult = this.crossScannerDeduplication(findings);
      deduplicatedFindings = dedupResult.findings;
      dedupResult.duplicates.forEach((primary, duplicate) => {
        duplicates.set(duplicate, primary);
      });
    }

    // Step 2: Group related findings
    const groups: RelatedFindingGroup[] = [];
    if (this.config.relatedFindingGrouping.enabled) {
      groups.push(...this.groupRelatedFindings(deduplicatedFindings));
    }

    // Step 3: Root cause analysis
    const rootCauses = new Map<string, RootCauseAnalysis>();
    if (this.config.rootCauseAnalysis.enabled) {
      for (const finding of deduplicatedFindings) {
        const analysis = this.analyzeRootCause(finding, deduplicatedFindings);
        if (analysis) {
          rootCauses.set(finding.id, analysis);
        }
      }
    }

    // Step 4: Impact analysis
    const impacts = new Map<string, ImpactAnalysis>();
    if (this.config.impactAnalysis.enabled) {
      for (const finding of deduplicatedFindings) {
        const impact = this.analyzeImpact(finding, deduplicatedFindings, groups);
        impacts.set(finding.id, impact);
      }
    }

    // Update findings with correlation data
    const correlatedFindings = this.enrichFindingsWithCorrelation(
      deduplicatedFindings,
      groups,
      rootCauses,
      impacts,
      duplicates
    );

    // Calculate statistics
    const statistics = {
      totalFindings: findings.length,
      uniqueFindings: correlatedFindings.length,
      duplicateCount: duplicates.size,
      groupCount: groups.length,
      averageGroupSize: groups.length > 0
        ? groups.reduce((sum, g) => sum + g.findings.length, 0) / groups.length
        : 0,
    };

    return {
      findings: correlatedFindings,
      groups,
      rootCauses,
      impacts,
      duplicates,
      statistics,
    };
  }

  /**
   * Build indices for efficient lookup
   */
  private buildIndices(findings: UnifiedFinding[]): void {
    this.findingsIndex.clear();
    this.assetIndex.clear();
    this.cveIndex.clear();
    this.cweIndex.clear();

    for (const finding of findings) {
      this.findingsIndex.set(finding.id, finding);

      // Index by asset
      const assetKey = this.getAssetKey(finding);
      if (assetKey) {
        if (!this.assetIndex.has(assetKey)) {
          this.assetIndex.set(assetKey, []);
        }
        this.assetIndex.get(assetKey)!.push(finding);
      }

      // Index by CVE
      const cveId = finding.vulnerability?.cve?.id || finding.vulnerability?.id;
      if (cveId) {
        if (!this.cveIndex.has(cveId)) {
          this.cveIndex.set(cveId, []);
        }
        this.cveIndex.get(cveId)!.push(finding);
      }

      // Index by CWE
      const cweId = finding.vulnerability?.classification;
      if (cweId && cweId.startsWith('CWE-')) {
        if (!this.cweIndex.has(cweId)) {
          this.cweIndex.set(cweId, []);
        }
        this.cweIndex.get(cweId)!.push(finding);
      }
    }
  }

  /**
   * Cross-scanner deduplication
   */
  private crossScannerDeduplication(
    findings: UnifiedFinding[]
  ): { findings: UnifiedFinding[]; duplicates: Map<string, string> } {
    const unique: UnifiedFinding[] = [];
    const duplicates = new Map<string, string>();
    const processed = new Set<string>();

    for (const finding of findings) {
      if (processed.has(finding.id)) {
        continue;
      }

      let isDuplicate = false;
      let primaryFinding = finding;

      // Check against already processed findings
      for (const existing of unique) {
        const similarity = this.calculateSimilarity(finding, existing);
        if (similarity >= this.config.crossScannerDeduplication.similarityThreshold) {
          // Determine which is primary (prefer higher severity, more recent, or specific scanner)
          primaryFinding = this.selectPrimaryFinding(finding, existing);
          const duplicateFinding = primaryFinding.id === finding.id ? existing : finding;

          duplicates.set(duplicateFinding.id, primaryFinding.id);
          isDuplicate = true;
          break;
        }
      }

      if (!isDuplicate) {
        unique.push(finding);
      } else {
        // Update primary finding with additional scanner info
        const primaryIndex = unique.findIndex(f => f.id === primaryFinding.id);
        if (primaryIndex >= 0) {
          const duplicateFinding = finding.id === primaryFinding.id
            ? findings.find(f => f.id !== primaryFinding.id && duplicates.get(f.id) === primaryFinding.id)
            : finding;

          if (duplicateFinding) {
            // Merge scanner information
            unique[primaryIndex] = this.mergeFindingMetadata(unique[primaryIndex], duplicateFinding);
          }
        }
      }

      processed.add(finding.id);
    }

    return { findings: unique, duplicates };
  }

  /**
   * Calculate similarity between two findings
   */
  private calculateSimilarity(f1: UnifiedFinding, f2: UnifiedFinding): number {
    let score = 0;
    let maxScore = 0;
    const strategies = this.config.crossScannerDeduplication.strategies;

    // CVE-based similarity
    if (strategies.includes('cve')) {
      const cve1 = f1.vulnerability?.cve?.id || f1.vulnerability?.id;
      const cve2 = f2.vulnerability?.cve?.id || f2.vulnerability?.id;
      if (cve1 && cve2) {
        maxScore += 0.4;
        if (cve1 === cve2) {
          score += 0.4;
        }
      }
    }

    // CWE-based similarity
    if (strategies.includes('cwe')) {
      const cwe1 = f1.vulnerability?.classification;
      const cwe2 = f2.vulnerability?.classification;
      if (cwe1 && cwe2) {
        maxScore += 0.2;
        if (cwe1 === cwe2) {
          score += 0.2;
        }
      }
    }

    // Location-based similarity
    if (strategies.includes('location')) {
      maxScore += 0.2;
      const loc1 = this.getLocationKey(f1);
      const loc2 = this.getLocationKey(f2);
      if (loc1 && loc2 && loc1 === loc2) {
        score += 0.2;
      } else if (loc1 && loc2) {
        // Check for similar paths (same file, different line)
        const similarity = this.locationSimilarity(loc1, loc2);
        score += 0.2 * similarity;
      }
    }

    // Asset-based similarity
    if (strategies.includes('asset')) {
      maxScore += 0.2;
      const asset1 = this.getAssetKey(f1);
      const asset2 = this.getAssetKey(f2);
      if (asset1 && asset2 && asset1 === asset2) {
        score += 0.2;
      }
    }

    return maxScore > 0 ? score / maxScore : 0;
  }

  /**
   * Select primary finding when duplicates are found
   */
  private selectPrimaryFinding(f1: UnifiedFinding, f2: UnifiedFinding): UnifiedFinding {
    // Prefer higher severity
    const severityOrder: Record<string, number> = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1,
    };
    if (severityOrder[f1.severity] !== severityOrder[f2.severity]) {
      return severityOrder[f1.severity] > severityOrder[f2.severity] ? f1 : f2;
    }

    // Prefer higher risk score
    if (f1.riskScore !== f2.riskScore) {
      return f1.riskScore > f2.riskScore ? f1 : f2;
    }

    // Prefer more recent
    if (f1.createdAt !== f2.createdAt) {
      return f1.createdAt > f2.createdAt ? f1 : f2;
    }

    // Prefer SAST over other sources (more detailed)
    const sourceOrder: Record<string, number> = {
      sast: 5,
      dast: 4,
      sca: 3,
      container: 2,
      iac: 1,
    };
    if (sourceOrder[f1.source] !== sourceOrder[f2.source]) {
      return sourceOrder[f1.source] > sourceOrder[f2.source] ? f1 : f2;
    }

    return f1; // Default to first
  }

  /**
   * Merge metadata from duplicate finding into primary
   */
  private mergeFindingMetadata(
    primary: UnifiedFinding,
    duplicate: UnifiedFinding
  ): UnifiedFinding {
    // Add scanner info to related findings
    if (!primary.relatedFindings) {
      primary.relatedFindings = [];
    }
    if (!primary.relatedFindings.includes(duplicate.id)) {
      primary.relatedFindings.push(duplicate.id);
    }

    // Merge scanner information if available
    if (duplicate.scannerId !== primary.scannerId) {
      // Keep both scanner IDs in metadata
      if (!primary.raw) {
        primary.raw = {};
      }
      if (!primary.raw.detectedByScanners) {
        primary.raw.detectedByScanners = [primary.scannerId];
      }
      if (!primary.raw.detectedByScanners.includes(duplicate.scannerId)) {
        primary.raw.detectedByScanners.push(duplicate.scannerId);
      }
    }

    return primary;
  }

  /**
   * Group related findings
   */
  private groupRelatedFindings(findings: UnifiedFinding[]): RelatedFindingGroup[] {
    const groups: RelatedFindingGroup[] = [];
    const processed = new Set<string>();
    const strategies = this.config.relatedFindingGrouping.groupingStrategies;

    for (const finding of findings) {
      if (processed.has(finding.id)) {
        continue;
      }

      let group: RelatedFindingGroup | null = null;

      // Try different grouping strategies
      if (strategies.includes('cwe-chain')) {
        group = this.groupByCWEChain(finding, findings, processed);
      }

      if (!group && strategies.includes('asset-chain')) {
        group = this.groupByAssetChain(finding, findings, processed);
      }

      if (!group && strategies.includes('dependency-chain')) {
        group = this.groupByDependencyChain(finding, findings, processed);
      }

      if (!group && strategies.includes('attack-path')) {
        group = this.groupByAttackPath(finding, findings, processed);
      }

      if (group) {
        groups.push(group);
        group.findings.forEach(id => processed.add(id));
      }
    }

    return groups;
  }

  /**
   * Group findings by CWE chain
   */
  private groupByCWEChain(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[],
    processed: Set<string>
  ): RelatedFindingGroup | null {
    const cwe = finding.vulnerability?.classification;
    if (!cwe) {
      return null;
    }

    const related = allFindings.filter(f => {
      if (processed.has(f.id) || f.id === finding.id) {
        return false;
      }
      return f.vulnerability?.classification === cwe &&
        this.getAssetKey(f) === this.getAssetKey(finding);
    });

    if (related.length === 0) {
      return null;
    }

    return {
      id: `group-${finding.id}`,
      primaryFinding: finding.id,
      findings: [finding.id, ...related.map(f => f.id)],
      relationshipType: 'related',
      confidence: 0.8,
      impactScore: this.calculateGroupImpactScore([finding, ...related]),
      createdAt: new Date(),
    };
  }

  /**
   * Group findings by asset chain
   */
  private groupByAssetChain(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[],
    processed: Set<string>
  ): RelatedFindingGroup | null {
    const assetKey = this.getAssetKey(finding);
    if (!assetKey) {
      return null;
    }

    const related = this.assetIndex.get(assetKey)?.filter(f => {
      if (processed.has(f.id) || f.id === finding.id) {
        return false;
      }
      // Only include if severity is similar or higher
      const severityOrder: Record<string, number> = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        info: 1,
      };
      return Math.abs(severityOrder[f.severity] - severityOrder[finding.severity]) <= 1;
    }) || [];

    if (related.length === 0) {
      return null;
    }

    return {
      id: `group-${finding.id}`,
      primaryFinding: finding.id,
      findings: [finding.id, ...related.map(f => f.id)],
      relationshipType: 'cluster',
      confidence: 0.7,
      impactScore: this.calculateGroupImpactScore([finding, ...related]),
      createdAt: new Date(),
    };
  }

  /**
   * Group findings by dependency chain
   */
  private groupByDependencyChain(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[],
    processed: Set<string>
  ): RelatedFindingGroup | null {
    // Find findings in the same dependency/component
    const component = finding.asset.component;
    if (!component) {
      return null;
    }

    const related = allFindings.filter(f => {
      if (processed.has(f.id) || f.id === finding.id) {
        return false;
      }
      return f.asset.component === component &&
        f.asset.applicationId === finding.asset.applicationId;
    });

    if (related.length === 0) {
      return null;
    }

    return {
      id: `group-${finding.id}`,
      primaryFinding: finding.id,
      findings: [finding.id, ...related.map(f => f.id)],
      relationshipType: 'chain',
      confidence: 0.75,
      impactScore: this.calculateGroupImpactScore([finding, ...related]),
      createdAt: new Date(),
    };
  }

  /**
   * Group findings by attack path
   */
  private groupByAttackPath(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[],
    processed: Set<string>
  ): RelatedFindingGroup | null {
    // This is a simplified version - full attack path analysis is in AttackPathAnalyzer
    // Here we group findings that could be part of the same attack chain
    const cwe = finding.vulnerability?.classification;
    if (!cwe) {
      return null;
    }

    // Common attack chains (simplified)
    const attackChains: Record<string, string[]> = {
      'CWE-79': ['CWE-79', 'CWE-352'], // XSS -> CSRF
      'CWE-89': ['CWE-89', 'CWE-20'], // SQL Injection -> Input Validation
      'CWE-352': ['CWE-352', 'CWE-79'], // CSRF -> XSS
    };

    const chain = attackChains[cwe];
    if (!chain) {
      return null;
    }

    const related = allFindings.filter(f => {
      if (processed.has(f.id) || f.id === finding.id) {
        return false;
      }
      return chain.includes(f.vulnerability?.classification || '') &&
        f.asset.applicationId === finding.asset.applicationId;
    });

    if (related.length === 0) {
      return null;
    }

    return {
      id: `group-${finding.id}`,
      primaryFinding: finding.id,
      findings: [finding.id, ...related.map(f => f.id)],
      relationshipType: 'chain',
      confidence: 0.7,
      impactScore: this.calculateGroupImpactScore([finding, ...related]),
      createdAt: new Date(),
    };
  }

  /**
   * Analyze root cause of a finding
   */
  private analyzeRootCause(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[]
  ): RootCauseAnalysis | null {
    // Check if this finding is likely a root cause or a symptom
    const cwe = finding.vulnerability?.classification;
    if (!cwe) {
      return null;
    }

    // Root causes are typically configuration or infrastructure issues
    const rootCauseCWEs = ['CWE-16', 'CWE-284', 'CWE-434', 'CWE-732']; // Configuration, Access Control, File Upload, Permissions
    const isLikelyRootCause = rootCauseCWEs.some(rc => cwe.includes(rc));

    if (isLikelyRootCause) {
      return {
        findingId: finding.id,
        rootCause: finding.id,
        chain: [finding.id],
        depth: 0,
        confidence: 0.8,
        analysis: {
          type: this.determineRootCauseType(finding),
          description: `This finding appears to be a root cause: ${finding.title}`,
          evidence: [finding.description],
        },
      };
    }

    // Look for related findings that might be root causes
    const related = this.findRelatedFindings(finding, allFindings);
    const rootCause = related.find(f => {
      const rc = f.vulnerability?.classification;
      return rc && rootCauseCWEs.some(cwe => rc.includes(cwe));
    });

    if (rootCause) {
      return {
        findingId: finding.id,
        rootCause: rootCause.id,
        chain: [rootCause.id, finding.id],
        depth: 1,
        confidence: 0.6,
        analysis: {
          type: this.determineRootCauseType(rootCause),
          description: `Root cause identified: ${rootCause.title}`,
          evidence: [rootCause.description, finding.description],
        },
      };
    }

    return null;
  }

  /**
   * Determine root cause type
   */
  private determineRootCauseType(finding: UnifiedFinding): RootCauseAnalysis['analysis']['type'] {
    const cwe = finding.vulnerability?.classification || '';
    if (cwe.includes('CWE-16') || cwe.includes('CWE-284')) {
      return 'configuration';
    }
    if (finding.source === 'iac' || finding.source === 'cspm') {
      return 'infrastructure';
    }
    if (finding.source === 'sast' || finding.source === 'dast') {
      return 'code';
    }
    if (finding.source === 'sca' || finding.source === 'container') {
      return 'dependency';
    }
    return 'unknown';
  }

  /**
   * Find related findings
   */
  private findRelatedFindings(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[]
  ): UnifiedFinding[] {
    const related: UnifiedFinding[] = [];
    const assetKey = this.getAssetKey(finding);

    // Same asset
    if (assetKey) {
      const sameAsset = this.assetIndex.get(assetKey) || [];
      related.push(...sameAsset.filter(f => f.id !== finding.id));
    }

    // Same CWE
    const cwe = finding.vulnerability?.classification;
    if (cwe) {
      const sameCWE = this.cweIndex.get(cwe) || [];
      related.push(...sameCWE.filter(f => f.id !== finding.id));
    }

    return related;
  }

  /**
   * Analyze impact of a finding
   */
  private analyzeImpact(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[],
    groups: RelatedFindingGroup[]
  ): ImpactAnalysis {
    // Map 'info' severity to 'low' for ImpactAnalysis compatibility
    const severity = finding.severity === 'info' ? 'low' : finding.severity;
    const directImpact = {
      affectedAssets: [this.getAssetKey(finding)].filter(Boolean) as string[],
      affectedApplications: finding.asset.applicationId ? [finding.asset.applicationId] : [],
      severity: severity as 'critical' | 'high' | 'medium' | 'low',
      businessImpact: finding.businessImpact || this.estimateBusinessImpact(finding),
    };

    // Find related findings
    const related = this.findRelatedFindings(finding, allFindings);
    const group = groups.find(g => g.findings.includes(finding.id));

    // Estimate potential exploits
    const potentialExploits = this.identifyPotentialExploits(finding, related);

    // Compliance impact
    const complianceImpact = finding.compliance?.frameworks || [];

    // Estimate remediation cost
    const estimatedRemediationCost = this.estimateRemediationCost(finding, related.length);

    const cascadingImpact = {
      relatedFindings: related.map(f => f.id),
      potentialExploits,
      complianceImpact,
      estimatedRemediationCost,
    };

    // Calculate overall impact score
    const overallImpactScore = this.calculateOverallImpactScore(
      directImpact,
      cascadingImpact,
      group
    );

    return {
      findingId: finding.id,
      directImpact,
      cascadingImpact,
      overallImpactScore,
    };
  }

  /**
   * Estimate business impact
   */
  private estimateBusinessImpact(finding: UnifiedFinding): number {
    let score = 0;

    // Base score from severity
    const severityScores: Record<string, number> = {
      critical: 90,
      high: 70,
      medium: 50,
      low: 30,
      info: 10,
    };
    score = severityScores[finding.severity] || 50;

    // Adjust based on asset criticality
    if (this.config.impactAnalysis.considerAssetCriticality) {
      // This would ideally come from asset inventory
      // For now, estimate based on application ID presence
      if (finding.asset.applicationId) {
        score += 10; // Applications are typically more critical
      }
    }

    // Adjust based on compliance impact
    if (finding.compliance?.frameworks && finding.compliance.frameworks.length > 0) {
      score += finding.compliance.frameworks.length * 5;
    }

    return Math.min(100, score);
  }

  /**
   * Identify potential exploits
   */
  private identifyPotentialExploits(
    finding: UnifiedFinding,
    related: UnifiedFinding[]
  ): string[] {
    const exploits: string[] = [];
    const cwe = finding.vulnerability?.classification;

    if (!cwe) {
      return exploits;
    }

    // Common exploit patterns
    const exploitPatterns: Record<string, string[]> = {
      'CWE-79': ['XSS to session hijacking', 'XSS to credential theft'],
      'CWE-89': ['SQL injection to data breach', 'SQL injection to privilege escalation'],
      'CWE-352': ['CSRF to unauthorized actions', 'CSRF to account takeover'],
      'CWE-434': ['File upload to RCE', 'File upload to data exfiltration'],
    };

    const pattern = Object.keys(exploitPatterns).find(p => cwe.includes(p));
    if (pattern) {
      exploits.push(...exploitPatterns[pattern]);
    }

    // Check if related findings enable additional exploits
    const relatedCWEs = related.map(f => f.vulnerability?.classification).filter(Boolean);
    if (relatedCWEs.includes('CWE-352') && cwe.includes('CWE-79')) {
      exploits.push('XSS + CSRF chain to account takeover');
    }

    return exploits;
  }

  /**
   * Estimate remediation cost
   */
  private estimateRemediationCost(finding: UnifiedFinding, relatedCount: number): number {
    // Base cost estimates (in hours)
    const baseCosts: Record<string, number> = {
      critical: 40,
      high: 20,
      medium: 10,
      low: 5,
      info: 2,
    };

    let cost = baseCosts[finding.severity] || 10;

    // Adjust for related findings
    cost += relatedCount * 2;

    // Adjust for remediation complexity
    if (finding.remediation.estimatedEffort === 'high') {
      cost *= 1.5;
    } else if (finding.remediation.estimatedEffort === 'low') {
      cost *= 0.7;
    }

    return Math.round(cost);
  }

  /**
   * Calculate overall impact score
   */
  private calculateOverallImpactScore(
    direct: ImpactAnalysis['directImpact'],
    cascading: ImpactAnalysis['cascadingImpact'],
    group: RelatedFindingGroup | undefined
  ): number {
    let score = direct.businessImpact;

    // Adjust for cascading impact
    if (cascading.relatedFindings.length > 0) {
      score += Math.min(20, cascading.relatedFindings.length * 2);
    }

    if (cascading.potentialExploits.length > 0) {
      score += cascading.potentialExploits.length * 5;
    }

    if (cascading.complianceImpact.length > 0) {
      score += cascading.complianceImpact.length * 3;
    }

    // Adjust for group impact
    if (group) {
      score += group.impactScore * 0.1;
    }

    return Math.min(100, Math.round(score));
  }

  /**
   * Calculate group impact score
   */
  private calculateGroupImpactScore(findings: UnifiedFinding[]): number {
    if (findings.length === 0) {
      return 0;
    }

    const maxSeverity = findings.reduce((max, f) => {
      const severityOrder: Record<string, number> = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
        info: 1,
      };
      return Math.max(max, severityOrder[f.severity] || 0);
    }, 0);

    const avgRiskScore = findings.reduce((sum, f) => sum + f.riskScore, 0) / findings.length;

    return Math.round((maxSeverity * 20) + (avgRiskScore * 0.6));
  }

  /**
   * Enrich findings with correlation data
   */
  private enrichFindingsWithCorrelation(
    findings: UnifiedFinding[],
    groups: RelatedFindingGroup[],
    rootCauses: Map<string, RootCauseAnalysis>,
    impacts: Map<string, ImpactAnalysis>,
    duplicates: Map<string, string>
  ): UnifiedFinding[] {
    return findings.map(finding => {
      const enriched = { ...finding };

      // Add duplicate information
      if (duplicates.has(finding.id)) {
        enriched.duplicateOf = duplicates.get(finding.id)!;
      }

      // Add related findings from groups
      const group = groups.find(g => g.findings.includes(finding.id));
      if (group) {
        if (!enriched.relatedFindings) {
          enriched.relatedFindings = [];
        }
        group.findings
          .filter(id => id !== finding.id)
          .forEach(id => {
            if (!enriched.relatedFindings!.includes(id)) {
              enriched.relatedFindings!.push(id);
            }
          });
      }

      // Add root cause information
      const rootCause = rootCauses.get(finding.id);
      if (rootCause && rootCause.rootCause !== finding.id) {
        if (!enriched.relatedFindings) {
          enriched.relatedFindings = [];
        }
        if (!enriched.relatedFindings.includes(rootCause.rootCause)) {
          enriched.relatedFindings.push(rootCause.rootCause);
        }
      }

      // Add impact information to raw data
      const impact = impacts.get(finding.id);
      if (impact) {
        if (!enriched.raw) {
          enriched.raw = {};
        }
        enriched.raw.correlationImpact = {
          overallImpactScore: impact.overallImpactScore,
          affectedAssets: impact.directImpact.affectedAssets.length,
          relatedFindingsCount: impact.cascadingImpact.relatedFindings.length,
          potentialExploits: impact.cascadingImpact.potentialExploits.length,
        };
      }

      return enriched;
    });
  }

  /**
   * Get asset key for indexing
   */
  private getAssetKey(finding: UnifiedFinding): string {
    const parts: string[] = [];
    if (finding.asset.applicationId) {
      parts.push(finding.asset.applicationId);
    }
    if (finding.asset.component) {
      parts.push(finding.asset.component);
    }
    if (finding.asset.location?.file?.path) {
      parts.push(finding.asset.location.file.path);
    } else if (finding.asset.location?.url?.original) {
      parts.push(finding.asset.location.url.original);
    } else if (finding.asset.location?.resource) {
      parts.push(finding.asset.location.resource);
    }
    return parts.join('|') || finding.id;
  }

  /**
   * Get location key for similarity
   */
  private getLocationKey(finding: UnifiedFinding): string | null {
    if (finding.asset.location?.file?.path) {
      return finding.asset.location.file.path;
    }
    if (finding.asset.location?.url?.original) {
      return finding.asset.location.url.original;
    }
    if (finding.asset.location?.resource) {
      return finding.asset.location.resource;
    }
    return null;
  }

  /**
   * Calculate location similarity
   */
  private locationSimilarity(loc1: string, loc2: string): number {
    // Same directory/file
    if (loc1 === loc2) {
      return 1.0;
    }

    // Same file, different line (for file paths)
    const path1 = loc1.split(':')[0];
    const path2 = loc2.split(':')[0];
    if (path1 === path2) {
      return 0.8;
    }

    // Same directory
    const dir1 = path1.split('/').slice(0, -1).join('/');
    const dir2 = path2.split('/').slice(0, -1).join('/');
    if (dir1 === dir2 && dir1.length > 0) {
      return 0.5;
    }

    return 0;
  }
}


