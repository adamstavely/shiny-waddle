/**
 * Base Scanner Adapter
 * 
 * Abstract base class for all scanner adapters.
 * Provides common functionality for normalizing scanner-specific formats.
 */

import { UnifiedFinding, ScannerSource, ScannerId } from '../../core/unified-finding-schema';

export interface ScannerFinding {
  [key: string]: any; // Scanner-specific format
}

export interface AdapterConfig {
  scannerId: ScannerId;
  source: ScannerSource;
  enabled: boolean;
  config?: Record<string, any>;
}

export abstract class BaseScannerAdapter {
  protected config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  /**
   * Normalize scanner-specific finding to UnifiedFinding
   * Some adapters may return an array (e.g., Trivy can have multiple findings per result)
   */
  abstract normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding | UnifiedFinding[];

  /**
   * Validate scanner finding format
   */
  abstract validate(finding: ScannerFinding): boolean;

  /**
   * Extract severity from scanner finding
   */
  protected abstract extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info';

  /**
   * Extract CVE/CWE information
   */
  protected extractVulnerabilityInfo(finding: ScannerFinding): {
    cveId?: string;
    cweId?: string;
    cvssScore?: number;
    cvssVector?: string;
  } {
    return {};
  }

  /**
   * Extract file location
   */
  protected extractFileLocation(finding: ScannerFinding): {
    file?: string;
    line?: number;
    column?: number;
  } {
    return {};
  }

  /**
   * Extract remediation information
   */
  protected extractRemediation(finding: ScannerFinding): {
    description: string;
    steps: string[];
    references: string[];
  } {
    return {
      description: '',
      steps: [],
      references: [],
    };
  }

  /**
   * Generate unique finding ID
   */
  protected generateFindingId(scannerFindingId: string): string {
    return `${this.config.scannerId}-${scannerFindingId}-${Date.now()}`;
  }

  /**
   * Calculate risk score
   */
  protected calculateRiskScore(
    severity: string,
    exploitability?: string,
    assetCriticality?: string
  ): number {
    const severityScores: Record<string, number> = {
      'critical': 100,
      'high': 75,
      'medium': 50,
      'low': 25,
      'info': 10,
    };

    const exploitabilityScores: Record<string, number> = {
      'exploitable': 1.0,
      'potentially-exploitable': 0.7,
      'not-exploitable': 0.3,
    };

    const criticalityScores: Record<string, number> = {
      'critical': 1.0,
      'high': 0.8,
      'medium': 0.6,
      'low': 0.4,
    };

    let score = severityScores[severity.toLowerCase()] || 50;
    
    if (exploitability) {
      score *= exploitabilityScores[exploitability] || 0.5;
    }
    
    if (assetCriticality) {
      score *= criticalityScores[assetCriticality.toLowerCase()] || 0.6;
    }

    return Math.round(score);
  }

  /**
   * Batch normalize findings
   */
  batchNormalize(findings: ScannerFinding[], metadata?: Record<string, any>): UnifiedFinding[] {
    const normalized: UnifiedFinding[] = [];
    for (const finding of findings) {
      if (!this.validate(finding)) continue;
      const result = this.normalize(finding, metadata);
      if (Array.isArray(result)) {
        normalized.push(...result);
      } else {
        normalized.push(result);
      }
    }
    return normalized;
  }
}

