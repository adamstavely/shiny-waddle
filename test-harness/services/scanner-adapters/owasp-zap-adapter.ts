/**
 * OWASP ZAP DAST Adapter
 * 
 * Normalizes OWASP ZAP alerts to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface OWASPZAPAlert {
  id: number;
  name: string;
  description: string;
  solution: string;
  reference: string;
  cweid?: number;
  wascid?: number;
  sourceid?: number;
  pluginId: string;
  alert: string;
  risk: 'Informational' | 'Low' | 'Medium' | 'High' | 'Critical';
  confidence: 'False Positive' | 'Low' | 'Medium' | 'High' | 'Confirmed';
  message?: {
    requestHeader?: string;
    requestBody?: string;
    responseHeader?: string;
    responseBody?: string;
  };
  url: string;
  method?: string;
  param?: string;
  attack?: string;
  evidence?: string;
  other?: string;
  otherInfo?: string;
  instances?: Array<{
    url: string;
    method: string;
    param?: string;
    attack?: string;
    evidence?: string;
  }>;
}

export class OWASPZAPAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'owasp-zap',
      source: 'dast',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const alert = finding as OWASPZAPAlert;
    return !!(
      alert.id &&
      alert.name &&
      alert.risk &&
      alert.url
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding {
    const alert = finding as OWASPZAPAlert;
    const severity = this.extractSeverity(alert);
    const urlParts = this.parseURL(alert.url);

    return {
      id: this.generateFindingId(`${alert.pluginId}-${alert.id}`),
      event: {
        kind: 'event',
        category: 'vulnerability',
        type: 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'dast',
      scannerId: 'owasp-zap',
      scannerFindingId: `${alert.pluginId}-${alert.id}`,
      title: alert.name,
      description: alert.description,
      severity,
      confidence: this.mapConfidence(alert.confidence),
      asset: {
        type: 'api',
        applicationId: metadata?.applicationId,
        component: alert.url,
        location: {
          url: {
            original: alert.url,
            scheme: urlParts.scheme,
            domain: urlParts.domain,
            port: urlParts.port,
            path: urlParts.path,
            query: urlParts.query,
            fragment: urlParts.fragment,
          },
        },
      },
      vulnerability: {
        id: alert.cweid ? `CWE-${alert.cweid}` : undefined,
        classification: alert.cweid ? `CWE-${alert.cweid}` : undefined,
        severity,
        scanner: {
          vendor: 'OWASP',
          name: 'ZAP',
          version: metadata?.zapVersion,
        },
      },
      threat: alert.cweid ? {
        framework: 'CWE',
        technique: {
          id: `CWE-${alert.cweid}`,
          reference: `https://cwe.mitre.org/data/definitions/${alert.cweid}.html`,
        },
      } : undefined,
      remediation: {
        description: alert.solution,
        steps: this.extractRemediationSteps(alert),
        references: this.extractReferences(alert),
        automated: false,
      },
      network: {
        protocol: urlParts.scheme?.toUpperCase() || 'HTTP',
        direction: 'inbound',
        transport: 'tcp',
      },
      status: 'open',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity, this.mapExploitability(alert)),
      raw: alert,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const alert = finding as OWASPZAPAlert;
    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'Critical': 'critical',
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Informational': 'info',
    };
    return mapping[alert.risk] || 'medium';
  }

  private mapConfidence(confidence: string): 'confirmed' | 'firm' | 'tentative' {
    const mapping: Record<string, 'confirmed' | 'firm' | 'tentative'> = {
      'Confirmed': 'confirmed',
      'High': 'firm',
      'Medium': 'firm',
      'Low': 'tentative',
      'False Positive': 'tentative',
    };
    return mapping[confidence] || 'firm';
  }

  private mapExploitability(alert: OWASPZAPAlert): 'exploitable' | 'potentially-exploitable' | 'not-exploitable' {
    if (alert.confidence === 'Confirmed' || alert.confidence === 'High') {
      return 'exploitable';
    }
    if (alert.confidence === 'Medium') {
      return 'potentially-exploitable';
    }
    return 'not-exploitable';
  }

  private parseURL(url: string): {
    scheme?: string;
    domain?: string;
    port?: number;
    path?: string;
    query?: string;
    fragment?: string;
  } {
    try {
      const urlObj = new URL(url);
      return {
        scheme: urlObj.protocol.replace(':', ''),
        domain: urlObj.hostname,
        port: urlObj.port ? parseInt(urlObj.port) : undefined,
        path: urlObj.pathname,
        query: urlObj.search.replace('?', ''),
        fragment: urlObj.hash.replace('#', ''),
      };
    } catch {
      return {};
    }
  }

  private extractRemediationSteps(alert: OWASPZAPAlert): string[] {
    const steps: string[] = [];
    
    if (alert.solution) {
      steps.push(alert.solution);
    }
    
    if (alert.param) {
      steps.push(`Review and sanitize parameter: ${alert.param}`);
    }
    
    if (alert.attack) {
      steps.push(`Prevent attack pattern: ${alert.attack}`);
    }
    
    return steps.length > 0 ? steps : ['Review and fix the security issue'];
  }

  private extractReferences(alert: OWASPZAPAlert): string[] {
    const refs: string[] = [];
    
    if (alert.cweid) {
      refs.push(`https://cwe.mitre.org/data/definitions/${alert.cweid}.html`);
    }
    
    if (alert.reference) {
      refs.push(alert.reference);
    }
    
    if (alert.wascid) {
      refs.push(`https://webappsec.org/wasc/${alert.wascid}`);
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

