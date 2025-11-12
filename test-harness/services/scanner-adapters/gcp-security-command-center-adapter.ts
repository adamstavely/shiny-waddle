/**
 * GCP Security Command Center CSPM Adapter
 * 
 * Normalizes GCP Security Command Center findings to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface GCPSecurityCommandCenterFinding {
  name: string;
  parent: string;
  resourceName: string;
  state: 'ACTIVE' | 'INACTIVE';
  category: string;
  externalUri?: string;
  sourceProperties: {
    ScannerName?: string;
    FindingClass?: string;
    State?: string;
    Severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    FindingProviderId?: string;
    FindingProviderName?: string;
    FindingId?: string;
    FindingSource?: string;
    FindingSourceId?: string;
    FindingSourceUrl?: string;
    FindingSourceUpdateTime?: string;
    FindingSourceCreateTime?: string;
    FindingSourceSeverity?: string;
    FindingSourceCategory?: string;
    FindingSourceDescription?: string;
    FindingSourceRecommendation?: string;
    FindingSourceRemediation?: string;
    FindingSourceCompliance?: string[];
    FindingSourceCVE?: string;
    FindingSourceCWE?: string;
    FindingSourceCVSS?: number;
    FindingSourceExploitability?: string;
    FindingSourceConfidence?: number;
    FindingSourceAssetType?: string;
    FindingSourceAssetId?: string;
    FindingSourceAssetName?: string;
    FindingSourceAssetLocation?: string;
    FindingSourceAssetProject?: string;
    FindingSourceAssetZone?: string;
    FindingSourceAssetRegion?: string;
    FindingSourceAssetLabels?: Record<string, string>;
    FindingSourceAssetTags?: string[];
    FindingSourceAssetMetadata?: Record<string, any>;
    [key: string]: any;
  };
  securityMarks?: {
    marks?: Record<string, string>;
  };
  eventTime?: string;
  createTime?: string;
  updateTime?: string;
}

export class GCPSecurityCommandCenterAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'gcp-security-command-center',
      source: 'cspm',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const gcpFinding = finding as GCPSecurityCommandCenterFinding;
    return !!(
      gcpFinding.name &&
      gcpFinding.resourceName &&
      gcpFinding.sourceProperties
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding {
    const gcpFinding = finding as GCPSecurityCommandCenterFinding;
    const severity = this.extractSeverity(gcpFinding);
    const props = gcpFinding.sourceProperties;

    return {
      id: this.generateFindingId(gcpFinding.name),
      event: {
        kind: 'event',
        category: 'security',
        type: props.FindingClass === 'THREAT' ? 'threat' : 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'cspm',
      scannerId: 'gcp-security-command-center',
      scannerFindingId: gcpFinding.name,
      title: props.FindingSourceDescription || props.FindingProviderName || gcpFinding.category || 'GCP Security Finding',
      description: props.FindingSourceDescription || props.FindingSourceRecommendation || 
                   `Security finding in ${gcpFinding.resourceName}`,
      severity,
      confidence: props.FindingSourceConfidence 
        ? (props.FindingSourceConfidence >= 0.8 ? 'confirmed' : 
           props.FindingSourceConfidence >= 0.5 ? 'firm' : 'tentative')
        : 'firm',
      asset: {
        type: 'infrastructure',
        applicationId: metadata?.applicationId,
        component: gcpFinding.resourceName,
        location: {
          resource: gcpFinding.resourceName,
          region: props.FindingSourceAssetRegion || props.FindingSourceAssetZone,
        },
      },
      host: {
        name: props.FindingSourceAssetName || gcpFinding.resourceName,
        id: gcpFinding.resourceName,
      },
      compliance: this.extractCompliance(gcpFinding),
      vulnerability: {
        severity,
        cveId: props.FindingSourceCVE,
        cweId: props.FindingSourceCWE,
        cvssScore: props.FindingSourceCVSS,
        exploitability: this.mapExploitability(props.FindingSourceExploitability),
        scanner: {
          vendor: 'Google',
          name: 'Security Command Center',
        },
      },
      remediation: {
        description: props.FindingSourceRemediation || props.FindingSourceRecommendation || 
                     'Review and fix the security issue in GCP',
        steps: this.extractRemediationSteps(gcpFinding),
        references: props.FindingSourceUrl ? [props.FindingSourceUrl] : 
                   (gcpFinding.externalUri ? [gcpFinding.externalUri] : []),
        automated: false,
      },
      status: this.mapStatus(gcpFinding.state),
      createdAt: gcpFinding.createTime ? new Date(gcpFinding.createTime) : 
                 (props.FindingSourceCreateTime ? new Date(props.FindingSourceCreateTime) : new Date()),
      updatedAt: gcpFinding.updateTime ? new Date(gcpFinding.updateTime) : 
                 (props.FindingSourceUpdateTime ? new Date(props.FindingSourceUpdateTime) : new Date()),
      riskScore: this.calculateRiskScore(severity, props.FindingSourceConfidence),
      raw: gcpFinding,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const gcpFinding = finding as GCPSecurityCommandCenterFinding;
    const severity = gcpFinding.sourceProperties.Severity || 
                     gcpFinding.sourceProperties.FindingSourceSeverity;
    
    if (!severity) return 'medium';

    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'CRITICAL': 'critical',
      'HIGH': 'high',
      'MEDIUM': 'medium',
      'LOW': 'low',
      'INFO': 'info',
      'INFORMATIONAL': 'info',
    };
    return mapping[severity.toUpperCase()] || 'medium';
  }

  private extractCompliance(gcpFinding: GCPSecurityCommandCenterFinding): UnifiedFinding['compliance'] {
    const frameworks: string[] = [];
    const controls: string[] = [];

    const compliance = gcpFinding.sourceProperties.FindingSourceCompliance;
    if (compliance && Array.isArray(compliance)) {
      compliance.forEach((comp: string) => {
        if (comp.includes('CIS')) frameworks.push('CIS-GCP');
        if (comp.includes('PCI')) frameworks.push('PCI-DSS');
        if (comp.includes('SOC')) frameworks.push('SOC2');
        if (comp.includes('HIPAA')) frameworks.push('HIPAA');
        if (comp.includes('ISO')) frameworks.push('ISO-27001');
        if (comp.includes('NIST')) frameworks.push('NIST-800-53');
        controls.push(comp);
      });
    }

    if (frameworks.length === 0) {
      frameworks.push('GCP-Security-Command-Center');
    }

    return {
      frameworks,
      controls,
      requirements: controls,
      rule: {
        id: gcpFinding.sourceProperties.FindingProviderId || gcpFinding.name,
        name: gcpFinding.sourceProperties.FindingProviderName || gcpFinding.category,
        category: gcpFinding.sourceProperties.ScannerName || 'GCP',
        description: gcpFinding.sourceProperties.FindingSourceDescription || '',
      },
    };
  }

  private extractRemediationSteps(gcpFinding: GCPSecurityCommandCenterFinding): string[] {
    const steps: string[] = [];
    const props = gcpFinding.sourceProperties;

    if (props.FindingSourceRemediation) {
      steps.push(props.FindingSourceRemediation);
    }

    if (props.FindingSourceRecommendation) {
      steps.push(props.FindingSourceRecommendation);
    }

    if (gcpFinding.resourceName) {
      steps.push(`Review GCP resource: ${gcpFinding.resourceName}`);
    }

    if (props.FindingSourceAssetProject) {
      steps.push(`Check project: ${props.FindingSourceAssetProject}`);
    }

    if (gcpFinding.externalUri) {
      steps.push(`See details: ${gcpFinding.externalUri}`);
    }

    return steps.length > 0 ? steps : ['Review and fix the security configuration in GCP Security Command Center'];
  }

  private mapStatus(state?: string): 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted' {
    if (!state) return 'open';
    
    const mapping: Record<string, 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted'> = {
      'ACTIVE': 'open',
      'INACTIVE': 'resolved',
    };
    return mapping[state] || 'open';
  }

  private mapExploitability(exploitability?: string): 'exploitable' | 'potentially-exploitable' | 'not-exploitable' {
    if (!exploitability) return 'potentially-exploitable';
    
    const lower = exploitability.toLowerCase();
    if (lower.includes('exploitable') || lower.includes('active')) {
      return 'exploitable';
    }
    if (lower.includes('potential') || lower.includes('possible')) {
      return 'potentially-exploitable';
    }
    return 'not-exploitable';
  }

  private calculateRiskScore(severity: string, confidence?: number): number {
    const baseScore = this.calculateBaseRiskScore(severity);
    
    if (confidence !== undefined) {
      // Adjust score based on confidence
      return Math.round(baseScore * (0.7 + confidence * 0.3));
    }
    
    return baseScore;
  }

  private calculateBaseRiskScore(severity: string): number {
    const mapping: Record<string, number> = {
      'critical': 90,
      'high': 70,
      'medium': 50,
      'low': 30,
      'info': 10,
    };
    return mapping[severity] || 50;
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

