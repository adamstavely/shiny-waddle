/**
 * AWS Security Hub CSPM Adapter
 * 
 * Normalizes AWS Security Hub findings to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface AWSSecurityHubFinding {
  Id: string;
  ProductArn: string;
  ProductName?: string;
  AwsAccountId: string;
  Region: string;
  GeneratorId: string;
  CreatedAt: string;
  UpdatedAt: string;
  SchemaVersion: string;
  Title: string;
  Description: string;
  Severity: {
    Label: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
    Normalized: number;
    Product?: number;
    Original?: string;
  };
  Compliance?: {
    Status: 'PASSED' | 'WARNING' | 'FAILED' | 'NOT_AVAILABLE';
    RelatedRequirements?: string[];
    StatusReasons?: Array<{
      ReasonCode: string;
      Description: string;
    }>;
  };
  ProductFields?: Record<string, string>;
  Resources: Array<{
    Type: string;
    Id: string;
    Partition?: string;
    Region?: string;
    Tags?: Record<string, string>;
    Details?: Record<string, any>;
  }>;
  Remediation?: {
    Recommendation?: {
      Text: string;
      Url?: string;
    };
  };
  Workflow?: {
    Status: 'NEW' | 'NOTIFIED' | 'RESOLVED' | 'SUPPRESSED';
  };
  RecordState?: 'ACTIVE' | 'ARCHIVED';
  RelatedFindings?: Array<{
    ProductArn: string;
    Id: string;
  }>;
}

export class AWSSecurityHubAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'aws-security-hub',
      source: 'cspm',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const hubFinding = finding as AWSSecurityHubFinding;
    return !!(
      hubFinding.Id &&
      hubFinding.Title &&
      hubFinding.Severity &&
      hubFinding.Resources &&
      hubFinding.Resources.length > 0
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding {
    const hubFinding = finding as AWSSecurityHubFinding;
    const severity = this.extractSeverity(hubFinding);
    const resource = hubFinding.Resources[0];

    return {
      id: this.generateFindingId(hubFinding.Id),
      event: {
        kind: 'event',
        category: hubFinding.Compliance ? 'compliance' : 'security',
        type: hubFinding.Compliance ? 'compliance-violation' : 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'cspm',
      scannerId: 'aws-security-hub',
      scannerFindingId: hubFinding.Id,
      title: hubFinding.Title,
      description: hubFinding.Description,
      severity,
      confidence: 'confirmed',
      asset: {
        type: 'infrastructure',
        applicationId: metadata?.applicationId,
        component: resource.Id,
        location: {
          resource: resource.Id,
          region: hubFinding.Region || resource.Region,
        },
      },
      host: {
        name: resource.Id,
        id: resource.Id,
      },
      compliance: hubFinding.Compliance ? {
        frameworks: this.extractFrameworks(hubFinding),
        controls: hubFinding.Compliance.RelatedRequirements || [],
        requirements: hubFinding.Compliance.RelatedRequirements || [],
        rule: {
          id: hubFinding.GeneratorId,
          name: hubFinding.Title,
          category: resource.Type,
          description: hubFinding.Description,
        },
      } : undefined,
      vulnerability: {
        severity,
        scanner: {
          vendor: 'AWS',
          name: 'Security Hub',
        },
      },
      remediation: {
        description: hubFinding.Remediation?.Recommendation?.Text || 'Review and fix the security issue',
        steps: this.extractRemediationSteps(hubFinding),
        references: hubFinding.Remediation?.Recommendation?.Url ? [hubFinding.Remediation.Recommendation.Url] : [],
        automated: false,
      },
      status: this.mapStatus(hubFinding.Workflow?.Status, hubFinding.RecordState),
      createdAt: new Date(hubFinding.CreatedAt),
      updatedAt: new Date(hubFinding.UpdatedAt),
      riskScore: this.calculateRiskScore(severity),
      relatedFindings: hubFinding.RelatedFindings?.map(f => this.generateFindingId(f.Id)),
      raw: hubFinding,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const hubFinding = finding as AWSSecurityHubFinding;
    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'CRITICAL': 'critical',
      'HIGH': 'high',
      'MEDIUM': 'medium',
      'LOW': 'low',
      'INFORMATIONAL': 'info',
    };
    return mapping[hubFinding.Severity.Label] || 'medium';
  }

  private extractFrameworks(hubFinding: AWSSecurityHubFinding): string[] {
    const frameworks: string[] = [];
    
    // AWS Security Hub findings often map to multiple compliance frameworks
    if (hubFinding.ProductFields) {
      if (hubFinding.ProductFields['aws/securityhub/CompanyName']) {
        frameworks.push('AWS-Security-Hub');
      }
      if (hubFinding.ProductFields['aws/securityhub/Compliance']) {
        const compliance = hubFinding.ProductFields['aws/securityhub/Compliance'];
        if (compliance.includes('CIS')) frameworks.push('CIS-AWS');
        if (compliance.includes('PCI')) frameworks.push('PCI-DSS');
        if (compliance.includes('SOC')) frameworks.push('SOC2');
      }
    }

    // Check compliance requirements
    if (hubFinding.Compliance?.RelatedRequirements) {
      for (const req of hubFinding.Compliance.RelatedRequirements) {
        if (req.includes('CIS')) frameworks.push('CIS-AWS');
        if (req.includes('PCI')) frameworks.push('PCI-DSS');
        if (req.includes('SOC')) frameworks.push('SOC2');
        if (req.includes('HIPAA')) frameworks.push('HIPAA');
      }
    }

    return frameworks.length > 0 ? frameworks : ['AWS-Security-Hub'];
  }

  private extractRemediationSteps(hubFinding: AWSSecurityHubFinding): string[] {
    const steps: string[] = [];
    
    if (hubFinding.Remediation?.Recommendation?.Text) {
      steps.push(hubFinding.Remediation.Recommendation.Text);
    }
    
    if (hubFinding.Resources[0]?.Type) {
      steps.push(`Review ${hubFinding.Resources[0].Type} resource: ${hubFinding.Resources[0].Id}`);
    }
    
    return steps.length > 0 ? steps : ['Review and fix the security configuration'];
  }

  private mapStatus(workflowStatus?: string, recordState?: string): 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted' {
    if (recordState === 'ARCHIVED') {
      return 'resolved';
    }
    
    if (workflowStatus) {
      const mapping: Record<string, 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted'> = {
        'NEW': 'open',
        'NOTIFIED': 'in-progress',
        'RESOLVED': 'resolved',
        'SUPPRESSED': 'risk-accepted',
      };
      return mapping[workflowStatus] || 'open';
    }
    
    return 'open';
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

