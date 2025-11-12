/**
 * Azure Security Center CSPM Adapter
 * 
 * Normalizes Azure Security Center findings to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface AzureSecurityCenterFinding {
  id: string;
  name: string;
  type: string;
  properties: {
    displayName: string;
    description: string;
    remediationDescription?: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational';
    state: 'Active' | 'Resolved' | 'Dismissed';
    timeGeneratedUtc: string;
    vendorName: string;
    alertType: string;
    intent?: string;
    resourceIdentifiers?: {
      azureResourceId?: string;
      workspaceId?: string;
      workspaceSubscriptionId?: string;
      workspaceResourceGroup?: string;
    };
    remediationSteps?: string[];
    extendedProperties?: Record<string, any>;
    compromisedEntity?: string;
    confidenceScore?: number;
    confidenceReasons?: Array<{
      type: string;
      reason: string;
    }>;
    sourceSystemIds?: string[];
    canBeInvestigated?: boolean;
    isIncident?: boolean;
    entities?: Array<{
      type: string;
      id: string;
      name?: string;
    }>;
    extendedLinks?: Array<{
      type: string;
      label: string;
      url: string;
    }>;
  };
  resourceGroup?: string;
  subscriptionId?: string;
}

export class AzureSecurityCenterAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'azure-security-center',
      source: 'cspm',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const azureFinding = finding as AzureSecurityCenterFinding;
    return !!(
      azureFinding.id &&
      azureFinding.properties &&
      azureFinding.properties.displayName &&
      azureFinding.properties.severity
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding {
    const azureFinding = finding as AzureSecurityCenterFinding;
    const severity = this.extractSeverity(azureFinding);
    const resourceId = azureFinding.properties.resourceIdentifiers?.azureResourceId || 
                       azureFinding.id;

    return {
      id: this.generateFindingId(azureFinding.id),
      event: {
        kind: 'event',
        category: 'security',
        type: azureFinding.properties.isIncident ? 'incident' : 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'cspm',
      scannerId: 'azure-security-center',
      scannerFindingId: azureFinding.id,
      title: azureFinding.properties.displayName,
      description: azureFinding.properties.description,
      severity,
      confidence: azureFinding.properties.confidenceScore 
        ? (azureFinding.properties.confidenceScore >= 0.8 ? 'confirmed' : 
           azureFinding.properties.confidenceScore >= 0.5 ? 'firm' : 'tentative')
        : 'firm',
      asset: {
        type: 'infrastructure',
        applicationId: metadata?.applicationId,
        component: resourceId,
        location: {
          resource: resourceId,
          region: this.extractRegion(resourceId),
        },
      },
      host: {
        name: azureFinding.properties.compromisedEntity || resourceId,
        id: resourceId,
      },
      compliance: this.extractCompliance(azureFinding),
      vulnerability: {
        severity,
        scanner: {
          vendor: 'Microsoft',
          name: 'Azure Security Center',
        },
        exploitability: azureFinding.properties.canBeInvestigated ? 'potentially-exploitable' : 'not-exploitable',
      },
      remediation: {
        description: azureFinding.properties.remediationDescription || 
                     azureFinding.properties.description,
        steps: azureFinding.properties.remediationSteps || 
               this.extractRemediationSteps(azureFinding),
        references: azureFinding.properties.extendedLinks?.map(link => link.url) || [],
        automated: false,
      },
      status: this.mapStatus(azureFinding.properties.state),
      createdAt: new Date(azureFinding.properties.timeGeneratedUtc),
      updatedAt: new Date(azureFinding.properties.timeGeneratedUtc),
      riskScore: this.calculateRiskScore(severity, azureFinding.properties.confidenceScore),
      relatedFindings: azureFinding.properties.sourceSystemIds?.map(id => this.generateFindingId(id)),
      raw: azureFinding,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const azureFinding = finding as AzureSecurityCenterFinding;
    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'Critical': 'critical',
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Informational': 'info',
    };
    return mapping[azureFinding.properties.severity] || 'medium';
  }

  private extractRegion(resourceId: string): string | undefined {
    // Azure resource IDs typically contain region information
    const match = resourceId.match(/\/locations\/([^\/]+)/);
    return match ? match[1] : undefined;
  }

  private extractCompliance(azureFinding: AzureSecurityCenterFinding): UnifiedFinding['compliance'] {
    const frameworks: string[] = [];
    const controls: string[] = [];

    // Azure Security Center findings often map to compliance frameworks
    if (azureFinding.properties.extendedProperties) {
      const compliance = azureFinding.properties.extendedProperties['compliance'];
      if (compliance) {
        if (typeof compliance === 'string') {
          if (compliance.includes('CIS')) frameworks.push('CIS-Azure');
          if (compliance.includes('PCI')) frameworks.push('PCI-DSS');
          if (compliance.includes('SOC')) frameworks.push('SOC2');
          if (compliance.includes('HIPAA')) frameworks.push('HIPAA');
          if (compliance.includes('ISO')) frameworks.push('ISO-27001');
        }
      }

      // Extract control IDs
      const controlId = azureFinding.properties.extendedProperties['controlId'];
      if (controlId) {
        controls.push(controlId);
      }
    }

    if (frameworks.length === 0) {
      frameworks.push('Azure-Security-Center');
    }

    return {
      frameworks,
      controls,
      requirements: controls,
      rule: {
        id: azureFinding.properties.alertType || azureFinding.id,
        name: azureFinding.properties.displayName,
        category: azureFinding.properties.vendorName || 'Azure',
        description: azureFinding.properties.description,
      },
    };
  }

  private extractRemediationSteps(azureFinding: AzureSecurityCenterFinding): string[] {
    const steps: string[] = [];

    if (azureFinding.properties.remediationDescription) {
      steps.push(azureFinding.properties.remediationDescription);
    }

    if (azureFinding.properties.resourceIdentifiers?.azureResourceId) {
      steps.push(`Review Azure resource: ${azureFinding.properties.resourceIdentifiers.azureResourceId}`);
    }

    if (azureFinding.properties.extendedLinks) {
      azureFinding.properties.extendedLinks.forEach(link => {
        steps.push(`${link.label}: ${link.url}`);
      });
    }

    return steps.length > 0 ? steps : ['Review and fix the security configuration in Azure Security Center'];
  }

  private mapStatus(state?: string): 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted' {
    if (!state) return 'open';
    
    const mapping: Record<string, 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted'> = {
      'Active': 'open',
      'Resolved': 'resolved',
      'Dismissed': 'risk-accepted',
    };
    return mapping[state] || 'open';
  }

  private calculateRiskScore(severity: string, confidenceScore?: number): number {
    const baseScore = this.calculateBaseRiskScore(severity);
    
    if (confidenceScore !== undefined) {
      // Adjust score based on confidence
      return Math.round(baseScore * (0.7 + confidenceScore * 0.3));
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

