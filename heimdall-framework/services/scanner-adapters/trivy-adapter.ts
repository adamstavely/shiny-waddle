/**
 * Trivy Container Adapter
 * 
 * Normalizes Trivy container scan results to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface TrivyResult {
  Target: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
}

export interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  PkgPath?: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  Title: string;
  Description: string;
  PrimaryURL?: string;
  PublishedDate?: string;
  LastModifiedDate?: string;
  CweIDs?: string[];
  CVSS?: {
    nvd?: {
      V3Score?: number;
      V3Vector?: string;
    };
    redhat?: {
      V3Score?: number;
      V3Vector?: string;
    };
  };
  References?: string[];
}

export interface TrivyMisconfiguration {
  Type: string;
  ID: string;
  AVOIDance: string;
  Severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNKNOWN';
  Title: string;
  Description: string;
  Message?: string;
  Resolution?: string;
  Status?: string;
  Layer?: {
    DiffID?: string;
  };
  IacMetadata?: {
    Resource?: string;
    Provider?: string;
    Service?: string;
    StartLine?: number;
    EndLine?: number;
  };
}

export class TrivyAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'trivy',
      source: 'container',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const result = finding as TrivyResult;
    return !!(
      result.Target &&
      result.Type &&
      (result.Vulnerabilities || result.Misconfigurations)
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding[] {
    const result = finding as TrivyResult;
    const findings: UnifiedFinding[] = [];

    // Normalize vulnerabilities
    if (result.Vulnerabilities) {
      for (const vuln of result.Vulnerabilities) {
        findings.push(this.normalizeVulnerability(vuln, result, metadata));
      }
    }

    // Normalize misconfigurations
    if (result.Misconfigurations) {
      for (const misconfig of result.Misconfigurations) {
        findings.push(this.normalizeMisconfiguration(misconfig, result, metadata));
      }
    }

    return findings;
  }

  private normalizeVulnerability(
    vuln: TrivyVulnerability,
    result: TrivyResult,
    metadata?: Record<string, any>
  ): UnifiedFinding {
    const severity = this.extractSeverity(vuln);
    const imageParts = this.parseImageName(result.Target);

    return {
      id: this.generateFindingId(`${vuln.VulnerabilityID}-${vuln.PkgName}`),
      event: {
        kind: 'event',
        category: 'vulnerability',
        type: 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'container',
      scannerId: 'trivy',
      scannerFindingId: vuln.VulnerabilityID,
      title: vuln.Title,
      description: vuln.Description,
      severity,
      confidence: 'confirmed',
      asset: {
        type: 'container',
        applicationId: metadata?.applicationId,
        component: vuln.PkgName,
        location: {
          resource: result.Target,
        },
      },
      host: {
        container: {
          id: imageParts.id,
          name: imageParts.name,
          image: {
            name: imageParts.name,
            tag: imageParts.tag,
          },
        },
      },
      vulnerability: {
        id: vuln.VulnerabilityID,
        cve: vuln.VulnerabilityID.startsWith('CVE-') ? {
          id: vuln.VulnerabilityID,
          description: vuln.Description,
          score: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.redhat?.V3Score ? {
            base: vuln.CVSS.nvd?.V3Score || vuln.CVSS.redhat?.V3Score || 0,
            version: '3.1',
            vector: vuln.CVSS.nvd?.V3Vector || vuln.CVSS.redhat?.V3Vector,
          } : undefined,
        } : undefined,
        classification: vuln.CweIDs?.[0],
        severity,
        scanner: {
          vendor: 'Aqua Security',
          name: 'Trivy',
          version: metadata?.trivyVersion,
        },
      },
      remediation: {
        description: vuln.FixedVersion ? `Upgrade to version ${vuln.FixedVersion}` : 'Review and apply security updates',
        steps: vuln.FixedVersion ? [
          `Update ${vuln.PkgName} from ${vuln.InstalledVersion} to ${vuln.FixedVersion}`,
          'Rebuild container image',
          'Test and deploy updated image',
        ] : [
          'Review vulnerability details',
          'Check for available patches or updates',
          'Consider alternative packages if no fix available',
        ],
        references: vuln.References || [],
        automated: !!vuln.FixedVersion,
      },
      status: 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: vuln,
    };
  }

  private normalizeMisconfiguration(
    misconfig: TrivyMisconfiguration,
    result: TrivyResult,
    metadata?: Record<string, any>
  ): UnifiedFinding {
    const severity = this.extractSeverity(misconfig);
    const imageParts = this.parseImageName(result.Target);

    return {
      id: this.generateFindingId(`${misconfig.ID}-${misconfig.Type}`),
      event: {
        kind: 'event',
        category: 'compliance',
        type: 'compliance-violation',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'container',
      scannerId: 'trivy',
      scannerFindingId: misconfig.ID,
      title: misconfig.Title,
      description: misconfig.Description,
      severity,
      confidence: 'firm',
      asset: {
        type: 'container',
        applicationId: metadata?.applicationId,
        component: result.Target,
        location: {
          resource: result.Target,
        },
      },
      host: {
        container: {
          id: imageParts.id,
          name: imageParts.name,
          image: {
            name: imageParts.name,
            tag: imageParts.tag,
          },
        },
      },
      compliance: {
        frameworks: ['Container-Best-Practices'],
        controls: [misconfig.ID],
        requirements: [],
        rule: {
          id: misconfig.ID,
          name: misconfig.Title,
          category: misconfig.Type,
          description: misconfig.Description,
        },
      },
      remediation: {
        description: misconfig.Resolution || misconfig.AVOIDance,
        steps: misconfig.Resolution ? [misconfig.Resolution] : ['Review and fix configuration'],
        references: [],
        automated: false,
      },
      status: 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: misconfig,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const vuln = finding as TrivyVulnerability | TrivyMisconfiguration;
    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'CRITICAL': 'critical',
      'HIGH': 'high',
      'MEDIUM': 'medium',
      'LOW': 'low',
      'UNKNOWN': 'info',
    };
    return mapping[vuln.Severity] || 'medium';
  }

  private parseImageName(target: string): {
    id?: string;
    name: string;
    tag: string;
  } {
    // Format: image:tag or registry/image:tag
    const parts = target.split(':');
    const name = parts.slice(0, -1).join(':') || target;
    const tag = parts[parts.length - 1] || 'latest';

    return {
      name,
      tag,
    };
  }

  private mapSeverityToECS(severity: string): number {
    const mapping: Record<string, number> = {
      'critical': 1000,
      'high': 750,
      'medium': 500,
      'low': 250,
      'info': 100,
    };
    return mapping[severity.toLowerCase()] || 500;
  }
}

