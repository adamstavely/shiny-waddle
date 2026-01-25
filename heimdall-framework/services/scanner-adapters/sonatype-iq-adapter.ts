/**
 * Sonatype IQ Adapter (SCA)
 * 
 * Normalizes Sonatype IQ vulnerability and policy violation reports to UnifiedFinding format
 * Supports component security analysis, license compliance, and policy violations
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface SonatypeIQComponent {
  packageUrl?: string;
  hash?: string;
  componentIdentifier?: {
    format: string;
    coordinates: {
      groupId?: string;
      artifactId?: string;
      version?: string;
      extension?: string;
    };
  };
  displayName?: string;
}

export interface SonatypeIQVulnerability {
  id: string;
  source?: string;
  cve?: string;
  cwe?: string;
  cvssScore?: number;
  cvssVector?: string;
  severity?: 'CRITICAL' | 'SEVERE' | 'MODERATE' | 'LOW' | 'INFO';
  title?: string;
  description?: string;
  reference?: string;
  publishedDate?: string;
  disclosedDate?: string;
  remediation?: {
    version?: string;
    description?: string;
  };
}

export interface SonatypeIQPolicyViolation {
  policyId: string;
  policyName: string;
  threatLevel: number;
  policyViolationId: string;
  constraintId: string;
  constraintName: string;
  stageId: string;
  reportTime?: string;
}

export interface SonatypeIQLicense {
  licenseId: string;
  licenseName: string;
  licenseText?: string;
  licenseThreatGroup?: number;
}

export interface SonatypeIQFinding {
  component: SonatypeIQComponent;
  vulnerabilities?: SonatypeIQVulnerability[];
  policyViolations?: SonatypeIQPolicyViolation[];
  licenses?: SonatypeIQLicense[];
  matchState?: string;
  pathnames?: string[];
  proprietary?: boolean;
  // Application context
  applicationId?: string;
  applicationName?: string;
  stage?: string;
  scanId?: string;
  scanTime?: string;
}

export interface SonatypeIQReport {
  reportDataUrl?: string;
  isError?: boolean;
  errorMessage?: string;
  application?: {
    id: string;
    publicId: string;
    name: string;
  };
  components?: SonatypeIQFinding[];
  summary?: {
    totalComponentCount?: number;
    vulnerableComponentCount?: number;
    criticalComponentCount?: number;
    severeComponentCount?: number;
    moderateComponentCount?: number;
    lowComponentCount?: number;
  };
}

export class SonatypeIQAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'sonatype-iq',
      source: 'sca',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const iqFinding = finding as SonatypeIQFinding | SonatypeIQReport;
    
    // Support both individual findings and full reports
    if ('components' in iqFinding) {
      // Full report - validate structure
      return !!(
        iqFinding.application?.id ||
        iqFinding.components ||
        iqFinding.summary
      );
    } else {
      // Individual finding
      return !!(
        iqFinding.component &&
        (iqFinding.vulnerabilities?.length > 0 ||
         iqFinding.policyViolations?.length > 0 ||
         iqFinding.licenses?.length > 0)
      );
    }
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding | UnifiedFinding[] {
    const iqFinding = finding as SonatypeIQFinding | SonatypeIQReport;
    
    // Handle full report format
    if ('components' in iqFinding && iqFinding.components) {
      const findings: UnifiedFinding[] = [];
      for (const component of iqFinding.components) {
        const componentFindings = this.normalizeComponent(component, {
          ...metadata,
          applicationId: iqFinding.application?.id || metadata?.applicationId,
          applicationName: iqFinding.application?.name || metadata?.applicationName,
        });
        findings.push(...componentFindings);
      }
      return findings;
    }
    
    // Handle individual finding
    return this.normalizeComponent(iqFinding as SonatypeIQFinding, metadata);
  }

  private normalizeComponent(
    component: SonatypeIQFinding,
    metadata?: Record<string, any>
  ): UnifiedFinding[] {
    const findings: UnifiedFinding[] = [];
    
    // Normalize vulnerabilities
    if (component.vulnerabilities && component.vulnerabilities.length > 0) {
      for (const vuln of component.vulnerabilities) {
        findings.push(this.normalizeVulnerability(component, vuln, metadata));
      }
    }
    
    // Normalize policy violations
    if (component.policyViolations && component.policyViolations.length > 0) {
      for (const violation of component.policyViolations) {
        findings.push(this.normalizePolicyViolation(component, violation, metadata));
      }
    }
    
    // Normalize license issues (if they're violations)
    if (component.licenses && component.licenses.length > 0) {
      for (const license of component.licenses) {
        if (license.licenseThreatGroup && license.licenseThreatGroup >= 7) {
          findings.push(this.normalizeLicenseIssue(component, license, metadata));
        }
      }
    }
    
    return findings.length > 0 ? findings : [this.normalizeComponentOnly(component, metadata)];
  }

  private normalizeVulnerability(
    component: SonatypeIQFinding,
    vuln: SonatypeIQVulnerability,
    metadata?: Record<string, any>
  ): UnifiedFinding {
    const severity = this.extractSeverity(vuln);
    const componentName = this.extractComponentName(component);
    const componentVersion = this.extractComponentVersion(component);
    
    return {
      id: this.generateFindingId(`${component.component?.hash || componentName}-${vuln.id}`),
      event: {
        kind: 'event',
        category: 'vulnerability',
        type: 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'sca',
      scannerId: 'sonatype-iq',
      scannerFindingId: vuln.id,
      title: vuln.title || vuln.cve || `Vulnerability in ${componentName}`,
      description: vuln.description || vuln.title || `Security vulnerability detected in ${componentName}`,
      severity,
      confidence: 'confirmed',
      asset: {
        type: 'dependency',
        applicationId: component.applicationId || metadata?.applicationId,
        component: componentName,
        location: {
          resource: component.component?.packageUrl || `${componentName}@${componentVersion}`,
        },
      },
      vulnerability: {
        id: vuln.cve || vuln.id,
        cve: vuln.cve ? {
          id: vuln.cve,
          description: vuln.description,
          score: vuln.cvssScore ? {
            base: vuln.cvssScore,
            version: vuln.cvssVector?.includes('CVSS:3') ? '3.1' : '2.0',
          } : undefined,
        } : undefined,
        classification: vuln.cwe,
        severity,
        scanner: {
          vendor: 'Sonatype',
          name: 'Sonatype IQ',
          version: metadata?.iqVersion,
        },
      },
      remediation: {
        description: this.extractRemediationDescription(vuln, component),
        steps: this.extractRemediationSteps(vuln, component),
        references: this.extractReferences(vuln),
        automated: !!vuln.remediation?.version,
      },
      status: 'open',
      createdAt: vuln.publishedDate ? new Date(vuln.publishedDate) : new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: {
        component,
        vulnerability: vuln,
      },
    };
  }

  private normalizePolicyViolation(
    component: SonatypeIQFinding,
    violation: SonatypeIQPolicyViolation,
    metadata?: Record<string, any>
  ): UnifiedFinding {
    const severity = this.mapThreatLevelToSeverity(violation.threatLevel);
    const componentName = this.extractComponentName(component);
    
    return {
      id: this.generateFindingId(`${component.component?.hash || componentName}-${violation.policyViolationId}`),
      event: {
        kind: 'event',
        category: 'security',
        type: 'policy-violation',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'sca',
      scannerId: 'sonatype-iq',
      scannerFindingId: violation.policyViolationId,
      title: `${violation.policyName}: ${violation.constraintName}`,
      description: `Policy violation: ${violation.constraintName} in component ${componentName}. Policy: ${violation.policyName}`,
      severity,
      confidence: 'confirmed',
      asset: {
        type: 'dependency',
        applicationId: component.applicationId || metadata?.applicationId,
        component: componentName,
        location: {
          resource: component.component?.packageUrl || componentName,
        },
      },
      vulnerability: {
        id: violation.constraintId,
        classification: violation.constraintName,
        severity,
        scanner: {
          vendor: 'Sonatype',
          name: 'Sonatype IQ',
          version: metadata?.iqVersion,
        },
      },
      remediation: {
        description: `Component ${componentName} violates policy ${violation.policyName}. Review and remediate according to policy requirements.`,
        steps: [
          `Review policy violation: ${violation.constraintName}`,
          `Assess component ${componentName}`,
          `Remediate or request policy exception if appropriate`,
        ],
        references: [],
        automated: false,
      },
      status: 'open',
      createdAt: violation.reportTime ? new Date(violation.reportTime) : new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: {
        component,
        policyViolation: violation,
      },
    };
  }

  private normalizeLicenseIssue(
    component: SonatypeIQFinding,
    license: SonatypeIQLicense,
    metadata?: Record<string, any>
  ): UnifiedFinding {
    const severity = this.mapLicenseThreatToSeverity(license.licenseThreatGroup || 0);
    const componentName = this.extractComponentName(component);
    
    return {
      id: this.generateFindingId(`${component.component?.hash || componentName}-license-${license.licenseId}`),
      event: {
        kind: 'event',
        category: 'security',
        type: 'license-violation',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'sca',
      scannerId: 'sonatype-iq',
      scannerFindingId: `license-${license.licenseId}`,
      title: `License Issue: ${license.licenseName}`,
      description: `Component ${componentName} uses license ${license.licenseName} with high threat level (${license.licenseThreatGroup}). Review license compliance requirements.`,
      severity,
      confidence: 'confirmed',
      asset: {
        type: 'dependency',
        applicationId: component.applicationId || metadata?.applicationId,
        component: componentName,
        location: {
          resource: component.component?.packageUrl || componentName,
        },
      },
      vulnerability: {
        id: license.licenseId,
        classification: license.licenseName,
        severity,
        scanner: {
          vendor: 'Sonatype',
          name: 'Sonatype IQ',
          version: metadata?.iqVersion,
        },
      },
      remediation: {
        description: `Review license ${license.licenseName} for component ${componentName}. Ensure compliance with organizational policies.`,
        steps: [
          `Review license terms: ${license.licenseName}`,
          `Assess compliance with organizational policies`,
          `Consider alternative component if license is not acceptable`,
        ],
        references: [],
        automated: false,
      },
      status: 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: {
        component,
        license,
      },
    };
  }

  private normalizeComponentOnly(
    component: SonatypeIQFinding,
    metadata?: Record<string, any>
  ): UnifiedFinding {
    const componentName = this.extractComponentName(component);
    
    return {
      id: this.generateFindingId(`${component.component?.hash || componentName}-component`),
      event: {
        kind: 'event',
        category: 'security',
        type: 'component-detected',
        action: 'detected',
        severity: 100,
      },
      source: 'sca',
      scannerId: 'sonatype-iq',
      scannerFindingId: component.component?.hash || componentName,
      title: `Component: ${componentName}`,
      description: `Component ${componentName} detected in scan`,
      severity: 'info',
      confidence: 'confirmed',
      asset: {
        type: 'dependency',
        applicationId: component.applicationId || metadata?.applicationId,
        component: componentName,
        location: {
          resource: component.component?.packageUrl || componentName,
        },
      },
      status: 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: 10,
      raw: component,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const vuln = finding as SonatypeIQVulnerability;
    
    if (vuln.severity) {
      const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
        'CRITICAL': 'critical',
        'SEVERE': 'high',
        'MODERATE': 'medium',
        'LOW': 'low',
        'INFO': 'info',
      };
      return mapping[vuln.severity] || 'medium';
    }
    
    // Fallback to CVSS score
    if (vuln.cvssScore !== undefined) {
      if (vuln.cvssScore >= 9.0) return 'critical';
      if (vuln.cvssScore >= 7.0) return 'high';
      if (vuln.cvssScore >= 4.0) return 'medium';
      if (vuln.cvssScore > 0) return 'low';
      return 'info';
    }
    
    return 'medium';
  }

  private extractComponentName(component: SonatypeIQFinding): string {
    if (component.component?.displayName) {
      return component.component.displayName;
    }
    if (component.component?.componentIdentifier?.coordinates) {
      const coords = component.component.componentIdentifier.coordinates;
      return `${coords.groupId || ''}:${coords.artifactId || ''}`.replace(/^:/, '');
    }
    if (component.component?.packageUrl) {
      return component.component.packageUrl;
    }
    return 'unknown-component';
  }

  private extractComponentVersion(component: SonatypeIQFinding): string {
    if (component.component?.componentIdentifier?.coordinates?.version) {
      return component.component.componentIdentifier.coordinates.version;
    }
    return 'unknown';
  }

  private mapThreatLevelToSeverity(threatLevel: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (threatLevel >= 9) return 'critical';
    if (threatLevel >= 7) return 'high';
    if (threatLevel >= 5) return 'medium';
    if (threatLevel >= 3) return 'low';
    return 'info';
  }

  private mapLicenseThreatToSeverity(threatGroup: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (threatGroup >= 9) return 'critical';
    if (threatGroup >= 7) return 'high';
    if (threatGroup >= 5) return 'medium';
    if (threatGroup >= 3) return 'low';
    return 'info';
  }

  private extractRemediationDescription(
    vuln: SonatypeIQVulnerability,
    component: SonatypeIQFinding
  ): string {
    const parts: string[] = [];
    
    if (vuln.remediation?.version) {
      parts.push(`Upgrade to version ${vuln.remediation.version} to remediate this vulnerability.`);
    }
    if (vuln.remediation?.description) {
      parts.push(vuln.remediation.description);
    }
    
    return parts.join(' ') || 'Review vulnerability details and apply recommended remediation.';
  }

  private extractRemediationSteps(
    vuln: SonatypeIQVulnerability,
    component: SonatypeIQFinding
  ): string[] {
    const steps: string[] = [];
    const componentName = this.extractComponentName(component);
    
    if (vuln.remediation?.version) {
      steps.push(`Upgrade ${componentName} to version ${vuln.remediation.version}`);
    } else {
      steps.push(`Review vulnerability ${vuln.cve || vuln.id} in component ${componentName}`);
      steps.push('Check for available patches or updates');
      steps.push('Consider alternative component if no fix is available');
    }
    
    return steps.length > 0 ? steps : ['Review and remediate vulnerability'];
  }

  private extractReferences(vuln: SonatypeIQVulnerability): string[] {
    const refs: string[] = [];
    
    if (vuln.cve) {
      refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${vuln.cve}`);
      refs.push(`https://nvd.nist.gov/vuln/detail/${vuln.cve}`);
    }
    
    if (vuln.cwe) {
      const cweNum = vuln.cwe.replace('CWE-', '');
      refs.push(`https://cwe.mitre.org/data/definitions/${cweNum}.html`);
    }
    
    if (vuln.reference) {
      refs.push(vuln.reference);
    }
    
    if (vuln.source) {
      refs.push(`https://ossindex.sonatype.org/vulnerability/${vuln.id}`);
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

