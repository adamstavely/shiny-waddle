/**
 * Attack Path Analyzer
 * 
 * Maps vulnerabilities to attack paths, identifies critical paths,
 * prioritizes findings based on attack paths, and provides attack surface visualization.
 */

import { UnifiedFinding } from '../core/unified-finding-schema';

export interface AttackPathConfig {
  enabled: boolean;
  maxPathDepth: number; // Maximum depth for attack path analysis
  includeTransitivePaths: boolean; // Include paths through multiple vulnerabilities
  prioritizeByExploitability: boolean;
  prioritizeByAssetCriticality: boolean;
  framework: 'mitre-attack' | 'owasp' | 'custom'; // Attack framework to use
}

export interface AttackStep {
  findingId: string;
  vulnerability: {
    cve?: string;
    cwe?: string;
    title: string;
    severity: string;
  };
  asset: {
    type: string;
    component?: string;
    applicationId?: string;
  };
  technique?: {
    id: string;
    name: string;
    framework: string;
  };
  exploitability: 'high' | 'medium' | 'low';
  prerequisites: string[]; // IDs of findings that must be exploited first
  impact: {
    dataAccess: boolean;
    privilegeEscalation: boolean;
    lateralMovement: boolean;
    persistence: boolean;
  };
}

export interface AttackPath {
  id: string;
  name: string;
  steps: AttackStep[];
  severity: 'critical' | 'high' | 'medium' | 'low';
  exploitability: 'high' | 'medium' | 'low';
  impact: {
    overall: number; // 0-100
    dataAccess: boolean;
    privilegeEscalation: boolean;
    lateralMovement: boolean;
    persistence: boolean;
    businessImpact: number; // 0-100
  };
  criticality: number; // 0-100, calculated based on severity, exploitability, and impact
  estimatedTimeToExploit: number; // Hours
  remediationPriority: number; // 0-100
  description: string;
  evidence: string[];
  createdAt: Date;
}

export interface AttackSurface {
  applicationId?: string;
  assetType: string;
  entryPoints: AttackStep[]; // Vulnerabilities that can be entry points
  paths: AttackPath[];
  criticalPaths: AttackPath[];
  totalVulnerabilities: number;
  exploitableVulnerabilities: number;
  riskScore: number; // 0-100
  coverage: {
    mitreTactics: string[];
    owaspCategories: string[];
  };
}

export interface AttackPathAnalysis {
  findings: UnifiedFinding[];
  paths: AttackPath[];
  criticalPaths: AttackPath[];
  attackSurfaces: Map<string, AttackSurface>; // Key: applicationId or asset identifier
  statistics: {
    totalPaths: number;
    criticalPathsCount: number;
    averagePathLength: number;
    mostCommonTechnique: string;
    highestRiskPath: string;
  };
  prioritization: Map<string, number>; // findingId -> priority score
}

export class AttackPathAnalyzer {
  private config: AttackPathConfig;
  private mitreTechniques: Map<string, MitreTechnique>;
  private cweToMitreMapping: Map<string, string[]>; // CWE -> MITRE technique IDs
  private attackChains: Map<string, string[]>; // Technique -> Prerequisite techniques

  constructor(config?: Partial<AttackPathConfig>) {
    this.config = {
      enabled: true,
      maxPathDepth: 5,
      includeTransitivePaths: true,
      prioritizeByExploitability: true,
      prioritizeByAssetCriticality: true,
      framework: 'mitre-attack',
      ...config,
    };

    this.mitreTechniques = new Map();
    this.cweToMitreMapping = new Map();
    this.attackChains = new Map();
    this.initializeAttackFramework();
  }

  /**
   * Analyze attack paths from findings
   */
  async analyze(findings: UnifiedFinding[]): Promise<AttackPathAnalysis> {
    if (!this.config.enabled || findings.length === 0) {
      return {
        findings,
        paths: [],
        criticalPaths: [],
        attackSurfaces: new Map(),
        statistics: {
          totalPaths: 0,
          criticalPathsCount: 0,
          averagePathLength: 0,
          mostCommonTechnique: '',
          highestRiskPath: '',
        },
        prioritization: new Map(),
      };
    }

    // Step 1: Map findings to attack steps
    const steps = this.mapFindingsToAttackSteps(findings);

    // Step 2: Build attack paths
    const paths = this.buildAttackPaths(steps, findings);

    // Step 3: Identify critical paths
    const criticalPaths = this.identifyCriticalPaths(paths);

    // Step 4: Build attack surfaces
    const attackSurfaces = this.buildAttackSurfaces(findings, steps, paths, criticalPaths);

    // Step 5: Prioritize findings based on attack paths
    const prioritization = this.prioritizeFindings(findings, paths, criticalPaths);

    // Step 6: Calculate statistics
    const statistics = this.calculateStatistics(paths, criticalPaths);

    return {
      findings,
      paths,
      criticalPaths,
      attackSurfaces,
      statistics,
      prioritization,
    };
  }

  /**
   * Map findings to attack steps
   */
  private mapFindingsToAttackSteps(findings: UnifiedFinding[]): AttackStep[] {
    return findings.map(finding => {
      const cwe = finding.vulnerability?.classification;
      const cve = finding.vulnerability?.cve?.id || finding.vulnerability?.id;

      // Map CWE to MITRE techniques
      const techniques = cwe ? this.mapCWEToMitreTechniques(cwe) : [];
      const primaryTechnique = techniques.length > 0 ? techniques[0] : undefined;

      // Determine exploitability
      const exploitability = this.assessExploitability(finding);

      // Determine impact
      const impact = this.assessImpact(finding, cwe);

      // Find prerequisites (findings that must be exploited first)
      const prerequisites = this.findPrerequisites(finding, findings);

      return {
        findingId: finding.id,
        vulnerability: {
          cve,
          cwe,
          title: finding.title,
          severity: finding.severity,
        },
        asset: {
          type: finding.asset.type,
          component: finding.asset.component,
          applicationId: finding.asset.applicationId,
        },
        technique: primaryTechnique ? {
          id: primaryTechnique.id,
          name: primaryTechnique.name,
          framework: 'mitre-attack',
        } : undefined,
        exploitability,
        prerequisites,
        impact,
      };
    });
  }

  /**
   * Map CWE to MITRE ATT&CK techniques
   */
  private mapCWEToMitreTechniques(cwe: string): MitreTechnique[] {
    const techniqueIds = this.cweToMitreMapping.get(cwe) || [];
    return techniqueIds
      .map(id => this.mitreTechniques.get(id))
      .filter((t): t is MitreTechnique => t !== undefined);
  }

  /**
   * Assess exploitability of a finding
   */
  private assessExploitability(finding: UnifiedFinding): 'high' | 'medium' | 'low' {
    // Base on severity and CVSS score
    if (finding.severity === 'critical' || finding.severity === 'high') {
      const cvssScore = finding.vulnerability?.cve?.score?.base || 0;
      if (cvssScore >= 9.0) {
        return 'high';
      }
      if (cvssScore >= 7.0) {
        return 'medium';
      }
      return 'low';
    }

    // Check if exploitability is mentioned in description
    const desc = finding.description.toLowerCase();
    if (desc.includes('exploit') || desc.includes('poc') || desc.includes('proof of concept')) {
      return 'high';
    }

    // Check for known exploitable CWEs
    const cwe = finding.vulnerability?.classification || '';
    const highExploitabilityCWEs = ['CWE-79', 'CWE-89', 'CWE-434', 'CWE-502'];
    if (highExploitabilityCWEs.some(c => cwe.includes(c))) {
      return 'high';
    }

    return finding.severity === 'medium' ? 'medium' : 'low';
  }

  /**
   * Assess impact of a finding
   */
  private assessImpact(finding: UnifiedFinding, cwe: string | undefined): AttackStep['impact'] {
    const impact: AttackStep['impact'] = {
      dataAccess: false,
      privilegeEscalation: false,
      lateralMovement: false,
      persistence: false,
    };

    if (!cwe) {
      return impact;
    }

    // Data access vulnerabilities
    const dataAccessCWEs = ['CWE-89', 'CWE-90', 'CWE-502', 'CWE-434'];
    if (dataAccessCWEs.some(c => cwe.includes(c))) {
      impact.dataAccess = true;
    }

    // Privilege escalation vulnerabilities
    const privilegeEscalationCWEs = ['CWE-269', 'CWE-284', 'CWE-732'];
    if (privilegeEscalationCWEs.some(c => cwe.includes(c))) {
      impact.privilegeEscalation = true;
    }

    // Lateral movement vulnerabilities
    const lateralMovementCWEs = ['CWE-79', 'CWE-352', 'CWE-434'];
    if (lateralMovementCWEs.some(c => cwe.includes(c))) {
      impact.lateralMovement = true;
    }

    // Persistence vulnerabilities
    const persistenceCWEs = ['CWE-434', 'CWE-502', 'CWE-306'];
    if (persistenceCWEs.some(c => cwe.includes(c))) {
      impact.persistence = true;
    }

    return impact;
  }

  /**
   * Find prerequisites for exploiting a finding
   */
  private findPrerequisites(
    finding: UnifiedFinding,
    allFindings: UnifiedFinding[]
  ): string[] {
    const prerequisites: string[] = [];
    const cwe = finding.vulnerability?.classification;

    if (!cwe) {
      return prerequisites;
    }

    // Find findings that enable this one
    // For example, CSRF (CWE-352) often requires XSS (CWE-79) or authentication bypass
    const prerequisiteMappings: Record<string, string[]> = {
      'CWE-352': ['CWE-79', 'CWE-284'], // CSRF needs XSS or auth bypass
      'CWE-434': ['CWE-79', 'CWE-20'], // File upload needs XSS or input validation bypass
      'CWE-502': ['CWE-434', 'CWE-20'], // Deserialization needs file upload or input validation
    };

    const requiredCWEs = prerequisiteMappings[cwe];
    if (requiredCWEs) {
      // Find findings with required CWEs in the same application
      const appId = finding.asset.applicationId;
      prerequisites.push(
        ...allFindings
          .filter(f => {
            if (f.id === finding.id || !f.asset.applicationId) {
              return false;
            }
            if (appId && f.asset.applicationId !== appId) {
              return false;
            }
            const fCWE = f.vulnerability?.classification;
            return fCWE && requiredCWEs.some(rc => fCWE.includes(rc));
          })
          .map(f => f.id)
      );
    }

    return prerequisites;
  }

  /**
   * Build attack paths from steps
   */
  private buildAttackPaths(
    steps: AttackStep[],
    findings: UnifiedFinding[]
  ): AttackPath[] {
    const paths: AttackPath[] = [];
    const processed = new Set<string>();

    // Find entry points (steps with no prerequisites or high exploitability)
    const entryPoints = steps.filter(step => {
      return step.prerequisites.length === 0 || step.exploitability === 'high';
    });

    for (const entryPoint of entryPoints) {
      if (processed.has(entryPoint.findingId)) {
        continue;
      }

      // Build paths starting from this entry point
      const pathsFromEntry = this.buildPathsFromStep(
        entryPoint,
        steps,
        findings,
        [entryPoint]
      );

      paths.push(...pathsFromEntry);
      processed.add(entryPoint.findingId);
    }

    // Also build paths for steps with prerequisites (transitive paths)
    if (this.config.includeTransitivePaths) {
      for (const step of steps) {
        if (processed.has(step.findingId) || step.prerequisites.length === 0) {
          continue;
        }

        const transitivePaths = this.buildTransitivePaths(step, steps, findings);
        paths.push(...transitivePaths);
      }
    }

    // Deduplicate and merge similar paths
    return this.deduplicatePaths(paths);
  }

  /**
   * Build paths starting from a step
   */
  private buildPathsFromStep(
    step: AttackStep,
    allSteps: AttackStep[],
    findings: UnifiedFinding[],
    currentPath: AttackStep[],
    depth: number = 0
  ): AttackPath[] {
    if (depth >= this.config.maxPathDepth) {
      return [];
    }

    const paths: AttackPath[] = [];

    // Find steps that can be reached from this step
    const nextSteps = allSteps.filter(nextStep => {
      if (currentPath.some(s => s.findingId === nextStep.findingId)) {
        return false; // Avoid cycles
      }

      // Check if this step enables the next step
      return this.canReachStep(step, nextStep, allSteps, findings);
    });

    if (nextSteps.length === 0) {
      // End of path, create attack path
      const path = this.createAttackPath(currentPath, findings);
      if (path) {
        paths.push(path);
      }
    } else {
      // Continue building paths
      for (const nextStep of nextSteps) {
        const extendedPath = [...currentPath, nextStep];
        const subPaths = this.buildPathsFromStep(
          nextStep,
          allSteps,
          findings,
          extendedPath,
          depth + 1
        );
        paths.push(...subPaths);
      }
    }

    return paths;
  }

  /**
   * Check if one step can reach another
   */
  private canReachStep(
    from: AttackStep,
    to: AttackStep,
    allSteps: AttackStep[],
    findings: UnifiedFinding[]
  ): boolean {
    // Direct prerequisite relationship
    if (to.prerequisites.includes(from.findingId)) {
      return true;
    }

    // Same asset/application enables chaining
    if (from.asset.applicationId && to.asset.applicationId) {
      if (from.asset.applicationId === to.asset.applicationId) {
        // Same application - check if techniques chain
        if (from.technique && to.technique) {
          const chain = this.attackChains.get(from.technique.id);
          if (chain && chain.includes(to.technique.id)) {
            return true;
          }
        }
      }
    }

    // Impact enables next step
    if (from.impact.lateralMovement && to.asset.applicationId) {
      return true; // Lateral movement enables access to other assets
    }

    if (from.impact.privilegeEscalation && to.asset.applicationId) {
      return true; // Privilege escalation enables access to protected resources
    }

    return false;
  }

  /**
   * Build transitive paths (paths through multiple vulnerabilities)
   */
  private buildTransitivePaths(
    step: AttackStep,
    allSteps: AttackStep[],
    findings: UnifiedFinding[]
  ): AttackPath[] {
    const paths: AttackPath[] = [];

    // Build path from prerequisites to this step
    if (step.prerequisites.length > 0) {
      const prerequisiteSteps = allSteps.filter(s =>
        step.prerequisites.includes(s.findingId)
      );

      for (const prereq of prerequisiteSteps) {
        const path = this.createAttackPath([prereq, step], findings);
        if (path) {
          paths.push(path);
        }
      }
    }

    return paths;
  }

  /**
   * Create an attack path from steps
   */
  private createAttackPath(
    steps: AttackStep[],
    findings: UnifiedFinding[]
  ): AttackPath | null {
    if (steps.length === 0) {
      return null;
    }

    // Calculate path metrics
    const maxSeverity = steps.reduce((max, step) => {
      const severityOrder: Record<string, number> = {
        critical: 5,
        high: 4,
        medium: 3,
        low: 2,
      };
      return Math.max(max, severityOrder[step.vulnerability.severity] || 0);
    }, 0);

    const pathSeverity: AttackPath['severity'] =
      maxSeverity >= 5 ? 'critical' :
      maxSeverity >= 4 ? 'high' :
      maxSeverity >= 3 ? 'medium' : 'low';

    const maxExploitability = steps.reduce((max, step) => {
      const exploitOrder: Record<string, number> = { high: 3, medium: 2, low: 1 };
      return Math.max(max, exploitOrder[step.exploitability] || 0);
    }, 0);

    const pathExploitability: AttackPath['exploitability'] =
      maxExploitability >= 3 ? 'high' :
      maxExploitability >= 2 ? 'medium' : 'low';

    // Aggregate impact
    const impact: AttackPath['impact'] = {
      overall: 0,
      dataAccess: steps.some(s => s.impact.dataAccess),
      privilegeEscalation: steps.some(s => s.impact.privilegeEscalation),
      lateralMovement: steps.some(s => s.impact.lateralMovement),
      persistence: steps.some(s => s.impact.persistence),
      businessImpact: 0,
    };

    // Calculate overall impact score
    let impactScore = 0;
    if (impact.dataAccess) impactScore += 30;
    if (impact.privilegeEscalation) impactScore += 25;
    if (impact.lateralMovement) impactScore += 20;
    if (impact.persistence) impactScore += 25;
    impact.overall = Math.min(100, impactScore);

    // Estimate business impact
    const finding = findings.find(f => f.id === steps[0].findingId);
    impact.businessImpact = finding?.businessImpact || this.estimateBusinessImpact(steps, findings);

    // Calculate criticality
    const criticality = this.calculatePathCriticality(pathSeverity, pathExploitability, impact);

    // Estimate time to exploit
    const estimatedTimeToExploit = this.estimateTimeToExploit(steps, pathExploitability);

    // Calculate remediation priority
    const remediationPriority = this.calculateRemediationPriority(
      criticality,
      impact,
      steps.length
    );

    // Generate description
    const description = this.generatePathDescription(steps, findings);

    // Collect evidence
    const evidence = steps.map(step => {
      const finding = findings.find(f => f.id === step.findingId);
      return finding?.description || step.vulnerability.title;
    });

    return {
      id: `path-${steps.map(s => s.findingId).join('-')}`,
      name: this.generatePathName(steps),
      steps,
      severity: pathSeverity,
      exploitability: pathExploitability,
      impact,
      criticality,
      estimatedTimeToExploit,
      remediationPriority,
      description,
      evidence,
      createdAt: new Date(),
    };
  }

  /**
   * Identify critical paths
   */
  private identifyCriticalPaths(paths: AttackPath[]): AttackPath[] {
    return paths
      .filter(path => {
        // Critical if:
        // 1. High criticality score
        // 2. High exploitability
        // 3. High impact
        return (
          path.criticality >= 70 ||
          (path.exploitability === 'high' && path.impact.overall >= 60) ||
          (path.severity === 'critical' && path.impact.dataAccess)
        );
      })
      .sort((a, b) => b.criticality - a.criticality);
  }

  /**
   * Build attack surfaces
   */
  private buildAttackSurfaces(
    findings: UnifiedFinding[],
    steps: AttackStep[],
    paths: AttackPath[],
    criticalPaths: AttackPath[]
  ): Map<string, AttackSurface> {
    const surfaces = new Map<string, AttackSurface>();

    // Group by application
    const byApplication = new Map<string, { findings: UnifiedFinding[]; steps: AttackStep[] }>();

    for (const finding of findings) {
      const appId = finding.asset.applicationId || 'unknown';
      if (!byApplication.has(appId)) {
        byApplication.set(appId, { findings: [], steps: [] });
      }
      byApplication.get(appId)!.findings.push(finding);
    }

    for (const step of steps) {
      const appId = step.asset.applicationId || 'unknown';
      if (byApplication.has(appId)) {
        byApplication.get(appId)!.steps.push(step);
      }
    }

    // Create attack surface for each application
    for (const [appId, data] of byApplication.entries()) {
      const appPaths = paths.filter(path =>
        path.steps.some(step => step.asset.applicationId === appId)
      );
      const appCriticalPaths = criticalPaths.filter(path =>
        path.steps.some(step => step.asset.applicationId === appId)
      );

      const entryPoints = data.steps.filter(step =>
        step.prerequisites.length === 0 || step.exploitability === 'high'
      );

      const exploitableCount = data.steps.filter(s => s.exploitability !== 'low').length;

      // Calculate risk score
      const riskScore = this.calculateAttackSurfaceRiskScore(
        data.findings,
        appPaths,
        appCriticalPaths
      );

      // Get coverage
      const mitreTactics = new Set<string>();
      const owaspCategories = new Set<string>();

      for (const step of data.steps) {
        if (step.technique) {
          const technique = this.mitreTechniques.get(step.technique.id);
          if (technique) {
            mitreTactics.add(technique.tactic);
          }
        }
      }

      const surface: AttackSurface = {
        applicationId: appId !== 'unknown' ? appId : undefined,
        assetType: data.findings[0]?.asset.type || 'application',
        entryPoints,
        paths: appPaths,
        criticalPaths: appCriticalPaths,
        totalVulnerabilities: data.findings.length,
        exploitableVulnerabilities: exploitableCount,
        riskScore,
        coverage: {
          mitreTactics: Array.from(mitreTactics),
          owaspCategories: Array.from(owaspCategories),
        },
      };

      surfaces.set(appId, surface);
    }

    return surfaces;
  }

  /**
   * Prioritize findings based on attack paths
   */
  private prioritizeFindings(
    findings: UnifiedFinding[],
    paths: AttackPath[],
    criticalPaths: AttackPath[]
  ): Map<string, number> {
    const prioritization = new Map<string, number>();

    for (const finding of findings) {
      let priority = finding.riskScore || 50;

      // Boost priority if in critical path
      const inCriticalPath = criticalPaths.some(path =>
        path.steps.some(step => step.findingId === finding.id)
      );
      if (inCriticalPath) {
        priority += 30;
      }

      // Boost priority if in any attack path
      const inPath = paths.some(path =>
        path.steps.some(step => step.findingId === finding.id)
      );
      if (inPath) {
        priority += 15;
      }

      // Boost priority if it's an entry point
      const isEntryPoint = paths.some(path =>
        path.steps[0]?.findingId === finding.id
      );
      if (isEntryPoint) {
        priority += 10;
      }

      // Boost priority if it enables other findings
      const enablesOthers = paths.some(path => {
        const stepIndex = path.steps.findIndex(step => step.findingId === finding.id);
        return stepIndex >= 0 && stepIndex < path.steps.length - 1;
      });
      if (enablesOthers) {
        priority += 10;
      }

      // Adjust based on exploitability
      if (this.config.prioritizeByExploitability) {
        const step = paths
          .flatMap(p => p.steps)
          .find(s => s.findingId === finding.id);
        if (step) {
          if (step.exploitability === 'high') {
            priority += 15;
          } else if (step.exploitability === 'low') {
            priority -= 10;
          }
        }
      }

      // Adjust based on asset criticality
      if (this.config.prioritizeByAssetCriticality && finding.asset.applicationId) {
        // This would ideally come from asset inventory
        // For now, assume applications are critical
        priority += 5;
      }

      prioritization.set(finding.id, Math.min(100, Math.max(0, priority)));
    }

    return prioritization;
  }

  /**
   * Calculate statistics
   */
  private calculateStatistics(
    paths: AttackPath[],
    criticalPaths: AttackPath[]
  ): AttackPathAnalysis['statistics'] {
    const avgPathLength =
      paths.length > 0
        ? paths.reduce((sum, p) => sum + p.steps.length, 0) / paths.length
        : 0;

    const techniques = paths.flatMap(p => p.steps.map(s => s.technique?.id)).filter(Boolean) as string[];
    const techniqueCounts = new Map<string, number>();
    for (const tech of techniques) {
      techniqueCounts.set(tech, (techniqueCounts.get(tech) || 0) + 1);
    }

    const mostCommonTechnique = Array.from(techniqueCounts.entries())
      .sort((a, b) => b[1] - a[1])[0]?.[0] || '';

    const highestRiskPath = criticalPaths.length > 0
      ? criticalPaths.sort((a, b) => b.criticality - a.criticality)[0].id
      : '';

    return {
      totalPaths: paths.length,
      criticalPathsCount: criticalPaths.length,
      averagePathLength: Math.round(avgPathLength * 10) / 10,
      mostCommonTechnique,
      highestRiskPath,
    };
  }

  /**
   * Calculate path criticality
   */
  private calculatePathCriticality(
    severity: AttackPath['severity'],
    exploitability: AttackPath['exploitability'],
    impact: AttackPath['impact']
  ): number {
    const severityScores: Record<string, number> = {
      critical: 40,
      high: 30,
      medium: 20,
      low: 10,
    };

    const exploitabilityScores: Record<string, number> = {
      high: 30,
      medium: 20,
      low: 10,
    };

    let score = severityScores[severity] + exploitabilityScores[exploitability];

    // Add impact scores
    score += impact.overall * 0.3;

    return Math.min(100, Math.round(score));
  }

  /**
   * Estimate time to exploit
   */
  private estimateTimeToExploit(
    steps: AttackStep[],
    exploitability: AttackPath['exploitability']
  ): number {
    const baseTimes: Record<string, number> = {
      high: 2, // 2 hours
      medium: 8, // 8 hours
      low: 24, // 24 hours
    };

    const baseTime = baseTimes[exploitability] || 8;
    return baseTime * steps.length;
  }

  /**
   * Calculate remediation priority
   */
  private calculateRemediationPriority(
    criticality: number,
    impact: AttackPath['impact'],
    pathLength: number
  ): number {
    let priority = criticality;

    // Boost priority for high business impact
    priority += impact.businessImpact * 0.2;

    // Boost priority for shorter paths (easier to fix)
    if (pathLength <= 2) {
      priority += 10;
    }

    return Math.min(100, Math.round(priority));
  }

  /**
   * Estimate business impact
   */
  private estimateBusinessImpact(
    steps: AttackStep[],
    findings: UnifiedFinding[]
  ): number {
    const maxBusinessImpact = steps.reduce((max, step) => {
      const finding = findings.find(f => f.id === step.findingId);
      return Math.max(max, finding?.businessImpact || 0);
    }, 0);

    // Adjust based on path length (longer paths = more impact)
    return Math.min(100, maxBusinessImpact + (steps.length * 5));
  }

  /**
   * Generate path description
   */
  private generatePathDescription(
    steps: AttackStep[],
    findings: UnifiedFinding[]
  ): string {
    if (steps.length === 1) {
      return `Single-step attack: ${steps[0].vulnerability.title}`;
    }

    const descriptions = steps.map((step, index) => {
      const finding = findings.find(f => f.id === step.findingId);
      return `Step ${index + 1}: ${step.vulnerability.title}${finding?.asset.component ? ` in ${finding.asset.component}` : ''}`;
    });

    return `Multi-step attack path:\n${descriptions.join('\n')}`;
  }

  /**
   * Generate path name
   */
  private generatePathName(steps: AttackStep[]): string {
    if (steps.length === 1) {
      return steps[0].vulnerability.title;
    }

    const techniques = steps
      .map(s => s.technique?.name)
      .filter(Boolean)
      .join(' → ');

    return techniques || `Attack Path (${steps.length} steps)`;
  }

  /**
   * Deduplicate paths
   */
  private deduplicatePaths(paths: AttackPath[]): AttackPath[] {
    const unique = new Map<string, AttackPath>();

    for (const path of paths) {
      const key = path.steps.map(s => s.findingId).join('|');
      if (!unique.has(key)) {
        unique.set(key, path);
      } else {
        // Keep the one with higher criticality
        const existing = unique.get(key)!;
        if (path.criticality > existing.criticality) {
          unique.set(key, path);
        }
      }
    }

    return Array.from(unique.values());
  }

  /**
   * Calculate attack surface risk score
   */
  private calculateAttackSurfaceRiskScore(
    findings: UnifiedFinding[],
    paths: AttackPath[],
    criticalPaths: AttackPath[]
  ): number {
    let score = 0;

    // Base score from findings
    const avgRiskScore = findings.reduce((sum, f) => sum + (f.riskScore || 0), 0) / findings.length;
    score += avgRiskScore * 0.4;

    // Boost for critical paths
    score += criticalPaths.length * 10;

    // Boost for total paths
    score += paths.length * 2;

    return Math.min(100, Math.round(score));
  }

  /**
   * Initialize attack framework
   */
  private initializeAttackFramework(): void {
    // Initialize MITRE ATT&CK techniques (simplified)
    const commonTechniques: MitreTechnique[] = [
      { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access' },
      { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution' },
      { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
      { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access' },
      { id: 'T1083', name: 'File and Directory Discovery', tactic: 'Discovery' },
      { id: 'T1021', name: 'Remote Services', tactic: 'Lateral Movement' },
      { id: 'T1055', name: 'Process Injection', tactic: 'Defense Evasion' },
    ];

    for (const tech of commonTechniques) {
      this.mitreTechniques.set(tech.id, tech);
    }

    // Map common CWEs to MITRE techniques
    this.cweToMitreMapping.set('CWE-79', ['T1190', 'T1059']); // XSS
    this.cweToMitreMapping.set('CWE-89', ['T1190', 'T1059']); // SQL Injection
    this.cweToMitreMapping.set('CWE-352', ['T1190']); // CSRF
    this.cweToMitreMapping.set('CWE-434', ['T1190', 'T1059']); // File Upload
    this.cweToMitreMapping.set('CWE-502', ['T1059']); // Deserialization
    this.cweToMitreMapping.set('CWE-284', ['T1078']); // Access Control
    this.cweToMitreMapping.set('CWE-269', ['T1078']); // Privilege Escalation

    // Define attack chains (technique prerequisites)
    this.attackChains.set('T1190', ['T1059', 'T1078']); // Exploit -> Execution/Defense Evasion
    this.attackChains.set('T1059', ['T1083', 'T1021']); // Execution -> Discovery/Lateral Movement
  }
}

interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
}

