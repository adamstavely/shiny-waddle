/**
 * Normalization Engine
 * 
 * Orchestrates the conversion of scanner-specific findings to unified format.
 * Handles deduplication, enrichment, and validation.
 */

import { UnifiedFinding } from '../core/unified-finding-schema';
import { BaseScannerAdapter } from './scanner-adapters/base-adapter';
import { SonarQubeAdapter } from './scanner-adapters/sonarqube-adapter';
import { SnykAdapter } from './scanner-adapters/snyk-adapter';
import { OWASPZAPAdapter } from './scanner-adapters/owasp-zap-adapter';
import { CheckovAdapter } from './scanner-adapters/checkov-adapter';
import { TrivyAdapter } from './scanner-adapters/trivy-adapter';
import { AWSSecurityHubAdapter } from './scanner-adapters/aws-security-hub-adapter';
import { ECSAdapter } from './ecs-adapter';

export interface NormalizationConfig {
  deduplication: {
    enabled: boolean;
    strategy: 'exact' | 'fuzzy' | 'semantic';
    similarityThreshold?: number;
  };
  enrichment: {
    enabled: boolean;
    enrichCVE?: boolean;
    enrichCWE?: boolean;
    enrichCompliance?: boolean;
  };
  validation: {
    enabled: boolean;
    strictMode?: boolean;
  };
}

export interface ScannerResult {
  scannerId: string;
  source: string;
  findings: any[];
  metadata?: Record<string, any>;
}

export class NormalizationEngine {
  private adapters: Map<string, BaseScannerAdapter>;
  private ecsAdapter: ECSAdapter;
  private config: NormalizationConfig;

  constructor(config?: Partial<NormalizationConfig>) {
    this.config = {
      deduplication: {
        enabled: true,
        strategy: 'fuzzy',
        similarityThreshold: 0.8,
        ...config?.deduplication,
      },
      enrichment: {
        enabled: true,
        enrichCVE: true,
        enrichCWE: true,
        enrichCompliance: true,
        ...config?.enrichment,
      },
      validation: {
        enabled: true,
        strictMode: false,
        ...config?.validation,
      },
    };

    this.ecsAdapter = new ECSAdapter();
    this.adapters = new Map();
    this.initializeAdapters();
  }

  /**
   * Initialize scanner adapters
   */
  private initializeAdapters(): void {
    // SAST adapters
    this.adapters.set('sonarqube', new SonarQubeAdapter({}));
    
    // SCA adapters
    this.adapters.set('snyk', new SnykAdapter({}, 'sca'));
    this.adapters.set('snyk-container', new SnykAdapter({}, 'container'));
    
    // DAST adapters
    this.adapters.set('owasp-zap', new OWASPZAPAdapter({}));
    
    // IaC adapters
    this.adapters.set('checkov', new CheckovAdapter({}));
    
    // Container adapters
    this.adapters.set('trivy', new TrivyAdapter({}));
    
    // CSPM adapters
    this.adapters.set('aws-security-hub', new AWSSecurityHubAdapter({}));
    
    // TODO: Add more adapters as needed (Veracode, Checkmarx, Burp Suite, etc.)
  }

  /**
   * Register a custom adapter
   */
  registerAdapter(scannerId: string, adapter: BaseScannerAdapter): void {
    this.adapters.set(scannerId, adapter);
  }

  /**
   * Normalize findings from multiple scanners
   */
  async normalize(scannerResults: ScannerResult[]): Promise<UnifiedFinding[]> {
    const allFindings: UnifiedFinding[] = [];

    // Normalize each scanner's findings
    for (const result of scannerResults) {
      const adapter = this.adapters.get(result.scannerId);
      if (!adapter) {
        console.warn(`No adapter found for scanner: ${result.scannerId}`);
        continue;
      }

      try {
        const normalized = adapter.batchNormalize(result.findings, result.metadata);
        allFindings.push(...normalized);
      } catch (error) {
        console.error(`Error normalizing findings from ${result.scannerId}:`, error);
      }
    }

    // Enrich findings
    if (this.config.enrichment.enabled) {
      await this.enrichFindings(allFindings);
    }

    // Validate findings
    if (this.config.validation.enabled) {
      this.validateFindings(allFindings);
    }

    // Deduplicate findings
    if (this.config.deduplication.enabled) {
      return this.deduplicateFindings(allFindings);
    }

    return allFindings;
  }

  /**
   * Normalize a single scanner result
   */
  async normalizeSingle(scannerId: string, findings: any[], metadata?: Record<string, any>): Promise<UnifiedFinding[]> {
    const adapter = this.adapters.get(scannerId);
    if (!adapter) {
      throw new Error(`No adapter found for scanner: ${scannerId}`);
    }

    const normalized = adapter.batchNormalize(findings, metadata);

    if (this.config.enrichment.enabled) {
      await this.enrichFindings(normalized);
    }

    if (this.config.validation.enabled) {
      this.validateFindings(normalized);
    }

    return normalized;
  }

  /**
   * Convert findings to ECS format
   */
  toECS(findings: UnifiedFinding[]): any[] {
    return this.ecsAdapter.batchToECS(findings);
  }

  /**
   * Convert ECS documents to unified findings
   */
  fromECS(docs: any[]): UnifiedFinding[] {
    return this.ecsAdapter.batchFromECS(docs);
  }

  /**
   * Enrich findings with additional data
   */
  private async enrichFindings(findings: UnifiedFinding[]): Promise<void> {
    for (const finding of findings) {
      // Enrich CVE data if available
      if (this.config.enrichment.enrichCVE && finding.vulnerability?.cve?.id) {
        // TODO: Fetch CVE details from external API
        // For now, we'll use what's already in the finding
      }

      // Enrich CWE data if available
      if (this.config.enrichment.enrichCWE && finding.vulnerability?.classification) {
        // TODO: Fetch CWE details from external API
      }

      // Enrich compliance mapping
      if (this.config.enrichment.enrichCompliance && finding.vulnerability) {
        // Map vulnerabilities to compliance frameworks
        this.enrichComplianceMapping(finding);
      }
    }
  }

  /**
   * Enrich compliance mapping based on vulnerability
   */
  private enrichComplianceMapping(finding: UnifiedFinding): void {
    if (!finding.compliance) {
      finding.compliance = {
        frameworks: [],
        controls: [],
        requirements: [],
      };
    }

    // Map common vulnerabilities to compliance frameworks
    const cveId = finding.vulnerability?.cve?.id;
    if (cveId) {
      // Critical CVEs often map to multiple frameworks
      if (finding.severity === 'critical' || finding.severity === 'high') {
        if (!finding.compliance.frameworks.includes('SOC2')) {
          finding.compliance.frameworks.push('SOC2');
        }
        if (!finding.compliance.frameworks.includes('PCI-DSS')) {
          finding.compliance.frameworks.push('PCI-DSS');
        }
      }
    }

    // Map CWE to compliance
    const cweId = finding.vulnerability?.classification;
    if (cweId && cweId.startsWith('CWE-')) {
      // Common CWEs map to specific compliance requirements
      const cweNumber = cweId.replace('CWE-', '');
      if (['79', '89', '90'].includes(cweNumber)) {
        // SQL injection, XSS, etc. - critical for all frameworks
        if (!finding.compliance.frameworks.includes('OWASP')) {
          finding.compliance.frameworks.push('OWASP');
        }
      }
    }
  }

  /**
   * Validate findings
   */
  private validateFindings(findings: UnifiedFinding[]): void {
    for (const finding of findings) {
      const errors: string[] = [];

      if (!finding.id) errors.push('Missing id');
      if (!finding.title) errors.push('Missing title');
      if (!finding.severity) errors.push('Missing severity');
      if (!finding.source) errors.push('Missing source');
      if (!finding.scannerId) errors.push('Missing scannerId');
      if (finding.riskScore < 0 || finding.riskScore > 100) {
        errors.push('Invalid riskScore (must be 0-100)');
      }

      if (errors.length > 0) {
        if (this.config.validation.strictMode) {
          throw new Error(`Invalid finding ${finding.id}: ${errors.join(', ')}`);
        } else {
          console.warn(`Invalid finding ${finding.id}: ${errors.join(', ')}`);
        }
      }
    }
  }

  /**
   * Deduplicate findings
   */
  private deduplicateFindings(findings: UnifiedFinding[]): UnifiedFinding[] {
    if (this.config.deduplication.strategy === 'exact') {
      return this.exactDeduplication(findings);
    } else if (this.config.deduplication.strategy === 'fuzzy') {
      return this.fuzzyDeduplication(findings);
    } else {
      return findings; // Semantic deduplication would require ML/NLP
    }
  }

  /**
   * Exact deduplication - same CVE/rule on same asset
   */
  private exactDeduplication(findings: UnifiedFinding[]): UnifiedFinding[] {
    const seen = new Map<string, UnifiedFinding>();
    const duplicates: UnifiedFinding[] = [];

    for (const finding of findings) {
      const key = this.generateDeduplicationKey(finding);
      if (seen.has(key)) {
        const existing = seen.get(key)!;
        // Keep the one with higher severity or more recent
        if (this.isMoreSevere(finding, existing) || finding.createdAt > existing.createdAt) {
          duplicates.push(existing);
          seen.set(key, finding);
        } else {
          duplicates.push(finding);
        }
      } else {
        seen.set(key, finding);
      }
    }

    return Array.from(seen.values());
  }

  /**
   * Fuzzy deduplication - similar findings
   */
  private fuzzyDeduplication(findings: UnifiedFinding[]): UnifiedFinding[] {
    const unique: UnifiedFinding[] = [];
    const threshold = this.config.deduplication.similarityThreshold || 0.8;

    for (const finding of findings) {
      let isDuplicate = false;

      for (const existing of unique) {
        const similarity = this.calculateSimilarity(finding, existing);
        if (similarity >= threshold) {
          // Merge or keep the more severe one
          if (this.isMoreSevere(finding, existing)) {
            const index = unique.indexOf(existing);
            unique[index] = finding;
          }
          isDuplicate = true;
          break;
        }
      }

      if (!isDuplicate) {
        unique.push(finding);
      }
    }

    return unique;
  }

  /**
   * Generate deduplication key
   */
  private generateDeduplicationKey(finding: UnifiedFinding): string {
    const parts: string[] = [
      finding.vulnerability?.cve?.id || finding.vulnerability?.id || '',
      finding.scannerId,
      finding.asset.type,
      finding.asset.component || '',
      finding.asset.location?.file?.path || finding.asset.location?.url?.original || '',
    ];
    return parts.join('|');
  }

  /**
   * Calculate similarity between two findings
   */
  private calculateSimilarity(f1: UnifiedFinding, f2: UnifiedFinding): number {
    let score = 0;
    let maxScore = 0;

    // Same CVE/ID
    if (f1.vulnerability?.cve?.id && f2.vulnerability?.cve?.id) {
      if (f1.vulnerability.cve.id === f2.vulnerability.cve.id) {
        score += 0.4;
      }
      maxScore += 0.4;
    }

    // Same asset
    if (f1.asset.component === f2.asset.component) {
      score += 0.3;
    }
    maxScore += 0.3;

    // Same location
    const loc1 = f1.asset.location?.file?.path || f1.asset.location?.url?.original || '';
    const loc2 = f2.asset.location?.file?.path || f2.asset.location?.url?.original || '';
    if (loc1 === loc2) {
      score += 0.2;
    }
    maxScore += 0.2;

    // Similar title (simple string similarity)
    const title1 = f1.title.toLowerCase();
    const title2 = f2.title.toLowerCase();
    if (title1 === title2) {
      score += 0.1;
    } else if (this.stringSimilarity(title1, title2) > 0.7) {
      score += 0.05;
    }
    maxScore += 0.1;

    return maxScore > 0 ? score / maxScore : 0;
  }

  /**
   * Simple string similarity (Jaccard similarity)
   */
  private stringSimilarity(s1: string, s2: string): number {
    const words1 = new Set(s1.split(/\s+/));
    const words2 = new Set(s2.split(/\s+/));
    const intersection = new Set([...words1].filter(x => words2.has(x)));
    const union = new Set([...words1, ...words2]);
    return union.size > 0 ? intersection.size / union.size : 0;
  }

  /**
   * Check if finding1 is more severe than finding2
   */
  private isMoreSevere(f1: UnifiedFinding, f2: UnifiedFinding): boolean {
    const severityOrder: Record<string, number> = {
      'critical': 5,
      'high': 4,
      'medium': 3,
      'low': 2,
      'info': 1,
    };

    const s1 = severityOrder[f1.severity] || 0;
    const s2 = severityOrder[f2.severity] || 0;

    if (s1 !== s2) {
      return s1 > s2;
    }

    // If same severity, prefer higher risk score
    return f1.riskScore > f2.riskScore;
  }
}

