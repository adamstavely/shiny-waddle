/**
 * Clair Container Adapter
 * 
 * Normalizes Clair container vulnerability scan results to UnifiedFinding format
 * Clair is an open-source container vulnerability scanner
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface ClairVulnerability {
  id: string;
  name: string;
  description?: string;
  link?: string;
  severity: 'Unknown' | 'Negligible' | 'Low' | 'Medium' | 'High' | 'Critical';
  package: string;
  version?: string;
  fixedIn?: string;
  namespace?: string;
  feature?: {
    name: string;
    version?: string;
    versionFormat?: string;
    namespace?: string;
  };
}

export interface ClairLayer {
  hash: string;
  parentHash?: string;
  format?: string;
  index?: number;
  features?: ClairFeature[];
}

export interface ClairFeature {
  name: string;
  version?: string;
  versionFormat?: string;
  namespace?: string;
  vulnerabilities?: ClairVulnerability[];
  addedBy?: string;
}

export interface ClairVulnerabilityReport {
  image: string;
  unpatched?: ClairVulnerability[];
  layers?: ClairLayer[];
  vulnerabilities?: ClairVulnerability[];
  summary?: {
    total?: number;
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
    negligible?: number;
    unknown?: number;
  };
}

export interface ClairAPIResponse {
  image: string;
  vulnerabilities?: ClairVulnerability[];
  layers?: ClairLayer[];
}

export class ClairAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'clair',
      source: 'container',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const report = finding as ClairVulnerabilityReport | ClairAPIResponse;
    
    // Support both report format and API response format
    if ('image' in report) {
      return !!(
        report.image &&
        (report.vulnerabilities ||
         report.unpatched ||
         report.layers ||
         (report as ClairAPIResponse).vulnerabilities)
      );
    }
    
    // Support layer-based format
    if ('layers' in report && Array.isArray(report.layers)) {
      return report.layers.some(layer => 
        layer.features?.some(feature => feature.vulnerabilities && feature.vulnerabilities.length > 0)
      );
    }
    
    return false;
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding[] {
    const report = finding as ClairVulnerabilityReport | ClairAPIResponse;
    const findings: UnifiedFinding[] = [];
    
    // Extract image information
    const imageParts = this.parseImageName(report.image);
    
    // Normalize vulnerabilities from top-level array
    if (report.vulnerabilities && report.vulnerabilities.length > 0) {
      for (const vuln of report.vulnerabilities) {
        findings.push(this.normalizeVulnerability(vuln, imageParts, metadata));
      }
    }
    
    // Normalize unpatched vulnerabilities
    if ('unpatched' in report && report.unpatched && report.unpatched.length > 0) {
      for (const vuln of report.unpatched) {
        findings.push(this.normalizeVulnerability(vuln, imageParts, metadata));
      }
    }
    
    // Normalize vulnerabilities from layers
    if (report.layers && report.layers.length > 0) {
      for (const layer of report.layers) {
        if (layer.features) {
          for (const feature of layer.features) {
            if (feature.vulnerabilities && feature.vulnerabilities.length > 0) {
              for (const vuln of feature.vulnerabilities) {
                findings.push(this.normalizeVulnerability(vuln, imageParts, metadata, feature));
              }
            }
          }
        }
      }
    }
    
    return findings;
  }

  private normalizeVulnerability(
    vuln: ClairVulnerability,
    imageParts: { id?: string; name: string; tag: string },
    metadata?: Record<string, any>,
    feature?: ClairFeature
  ): UnifiedFinding {
    const severity = this.extractSeverity(vuln);
    const packageName = vuln.package || feature?.name || 'unknown';
    const packageVersion = vuln.version || feature?.version || 'unknown';
    
    return {
      id: this.generateFindingId(`${vuln.id}-${packageName}-${imageParts.name}`),
      event: {
        kind: 'event',
        category: 'vulnerability',
        type: 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'container',
      scannerId: 'clair',
      scannerFindingId: vuln.id,
      title: vuln.name || `Vulnerability in ${packageName}`,
      description: vuln.description || vuln.name || `Security vulnerability detected in ${packageName} ${packageVersion}`,
      severity,
      confidence: 'confirmed',
      asset: {
        type: 'container',
        applicationId: metadata?.applicationId,
        component: packageName,
        location: {
          resource: `${imageParts.name}:${imageParts.tag}`,
          file: {
            name: packageName,
          },
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
        id: vuln.id,
        cve: this.isCVE(vuln.id) ? {
          id: vuln.id,
          description: vuln.description,
          score: this.extractCVSSScore(vuln),
        } : undefined,
        classification: vuln.namespace || feature?.namespace,
        severity,
        scanner: {
          vendor: 'Quay',
          name: 'Clair',
          version: metadata?.clairVersion,
        },
      },
      remediation: {
        description: this.extractRemediationDescription(vuln, packageName, packageVersion),
        steps: this.extractRemediationSteps(vuln, packageName, packageVersion),
        references: this.extractReferences(vuln),
        automated: !!vuln.fixedIn,
      },
      status: 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: {
        vulnerability: vuln,
        feature,
      },
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const vuln = finding as ClairVulnerability;
    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'Critical': 'critical',
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Negligible': 'low',
      'Unknown': 'info',
    };
    return mapping[vuln.severity] || 'medium';
  }

  private isCVE(id: string): boolean {
    return /^CVE-\d{4}-\d{4,}$/.test(id);
  }

  private extractCVSSScore(vuln: ClairVulnerability): {
    base?: number;
    version?: string;
  } | undefined {
    // Clair doesn't always provide CVSS scores directly
    // We can infer from severity if needed
    const severityScores: Record<string, number> = {
      'Critical': 9.0,
      'High': 7.0,
      'Medium': 5.0,
      'Low': 3.0,
      'Negligible': 1.0,
    };
    
    const inferredScore = severityScores[vuln.severity];
    if (inferredScore) {
      return {
        base: inferredScore,
        version: '3.1',
      };
    }
    
    return undefined;
  }

  private parseImageName(image: string): {
    id?: string;
    name: string;
    tag: string;
  } {
    // Format: image:tag or registry/image:tag or registry/image@digest
    let name = image;
    let tag = 'latest';
    let id: string | undefined;
    
    // Handle digest format: image@sha256:digest
    if (image.includes('@')) {
      const [imgName, digest] = image.split('@');
      name = imgName;
      id = digest;
      // Try to extract tag if it exists before @
      if (imgName.includes(':')) {
        const parts = imgName.split(':');
        tag = parts[parts.length - 1];
        name = parts.slice(0, -1).join(':');
      }
    } else if (image.includes(':')) {
      // Handle tag format: image:tag
      const parts = image.split(':');
      tag = parts[parts.length - 1];
      name = parts.slice(0, -1).join(':');
    }
    
    return {
      id,
      name: name || image,
      tag,
    };
  }

  private extractRemediationDescription(
    vuln: ClairVulnerability,
    packageName: string,
    packageVersion: string
  ): string {
    const parts: string[] = [];
    
    if (vuln.fixedIn) {
      parts.push(`Upgrade ${packageName} to version ${vuln.fixedIn} or later to remediate this vulnerability.`);
    } else {
      parts.push(`Review vulnerability ${vuln.name || vuln.id} in ${packageName} ${packageVersion}.`);
      parts.push('Check for available patches or updates from the package maintainer.');
    }
    
    return parts.join(' ') || 'Review and apply recommended fixes.';
  }

  private extractRemediationSteps(
    vuln: ClairVulnerability,
    packageName: string,
    packageVersion: string
  ): string[] {
    const steps: string[] = [];
    
    if (vuln.fixedIn) {
      steps.push(`Update ${packageName} from ${packageVersion} to ${vuln.fixedIn} or later`);
      steps.push('Rebuild container image with updated package');
      steps.push('Test updated container image');
      steps.push('Deploy updated image to production');
    } else {
      steps.push(`Review vulnerability ${vuln.name || vuln.id} in ${packageName}`);
      steps.push('Check for available patches or security updates');
      steps.push('Consider alternative packages if no fix is available');
      steps.push('Apply workarounds if documented');
    }
    
    return steps.length > 0 ? steps : ['Review and remediate vulnerability'];
  }

  private extractReferences(vuln: ClairVulnerability): string[] {
    const refs: string[] = [];
    
    if (vuln.link) {
      refs.push(vuln.link);
    }
    
    if (this.isCVE(vuln.id)) {
      refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.id}`);
      refs.push(`https://nvd.nist.gov/vuln/detail/${vuln.id}`);
    }
    
    // Add Clair-specific reference if available
    if (vuln.namespace) {
      refs.push(`https://quay.io/repository/coreos/clair?tab=tags`);
    }
    
    return refs;
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

