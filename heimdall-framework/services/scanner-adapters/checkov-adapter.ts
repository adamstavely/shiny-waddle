/**
 * Checkov IaC Adapter
 * 
 * Normalizes Checkov IaC scan results to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface CheckovCheck {
  check_id: string;
  bc_check_id?: string;
  check_name: string;
  check_result: {
    result: 'PASSED' | 'FAILED' | 'SKIPPED';
    evaluated_keys: string[];
  };
  code_block?: Array<[number, string]>;
  file_path: string;
  file_line_range: [number, number];
  resource: string;
  guideline?: string;
  severity?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description?: string;
  short_description?: string;
  vulnerability_details?: {
    id?: string;
    cve_id?: string;
    cwe_id?: string;
    description?: string;
  };
  fixed_definition?: string;
  entity_tags?: Record<string, string>;
}

export class CheckovAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'checkov',
      source: 'iac',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const check = finding as CheckovCheck;
    return !!(
      check.check_id &&
      check.check_name &&
      check.check_result &&
      check.file_path &&
      check.resource
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding {
    const check = finding as CheckovCheck;
    const severity = this.extractSeverity(check);
    const filePath = this.extractFilePath(check.file_path);

    return {
      id: this.generateFindingId(`${check.check_id}-${check.resource}`),
      event: {
        kind: 'event',
        category: 'compliance',
        type: 'compliance-violation',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'iac',
      scannerId: 'checkov',
      scannerFindingId: check.check_id,
      title: check.check_name,
      description: check.description || check.short_description || check.check_name,
      severity,
      confidence: 'firm',
      asset: {
        type: 'iac',
        applicationId: metadata?.applicationId,
        component: check.resource,
        location: {
          file: {
            name: filePath.name,
            path: filePath.path,
            extension: filePath.extension,
            directory: filePath.directory,
          },
          line: check.file_line_range[0],
          resource: check.resource,
        },
      },
      vulnerability: check.vulnerability_details ? {
        id: check.vulnerability_details.cve_id,
        classification: check.vulnerability_details.cwe_id,
        severity,
        scanner: {
          vendor: 'Bridgecrew',
          name: 'Checkov',
          version: metadata?.checkovVersion,
        },
      } : undefined,
      compliance: {
        frameworks: this.extractFrameworks(check),
        controls: [check.check_id],
        requirements: [],
        rule: {
          id: check.check_id,
          name: check.check_name,
          category: 'IaC',
          description: check.guideline || check.description,
        },
      },
      remediation: {
        description: check.guideline || 'Review and fix the IaC configuration',
        steps: this.extractRemediationSteps(check),
        references: this.extractReferences(check),
        automated: !!check.fixed_definition,
      },
      status: check.check_result.result === 'FAILED' ? 'open' : 'resolved',
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: check,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const check = finding as CheckovCheck;
    if (check.severity) {
      const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
        'CRITICAL': 'critical',
        'HIGH': 'high',
        'MEDIUM': 'medium',
        'LOW': 'low',
      };
      return mapping[check.severity] || 'medium';
    }
    return 'medium';
  }

  private extractFilePath(filePath: string): {
    name: string;
    path: string;
    extension: string;
    directory: string;
  } {
    const pathParts = filePath.split('/');
    const fileName = pathParts[pathParts.length - 1] || filePath;
    const extMatch = fileName.match(/\.([^.]+)$/);
    const extension = extMatch ? extMatch[1] : '';
    const directory = pathParts.slice(0, -1).join('/');

    return {
      name: fileName,
      path: filePath,
      extension,
      directory,
    };
  }

  private extractFrameworks(check: CheckovCheck): string[] {
    const frameworks: string[] = [];
    
    if (check.entity_tags) {
      if (check.entity_tags['framework']) {
        frameworks.push(check.entity_tags['framework']);
      }
      if (check.entity_tags['compliance']) {
        frameworks.push(...check.entity_tags['compliance'].split(','));
      }
    }
    
    // Checkov checks often map to compliance frameworks
    if (check.check_id.includes('CKV_AWS') || check.check_id.includes('CKV2_AWS')) {
      frameworks.push('AWS-CIS');
    }
    if (check.check_id.includes('CKV_AZURE') || check.check_id.includes('CKV2_AZURE')) {
      frameworks.push('Azure-CIS');
    }
    if (check.check_id.includes('CKV_GCP') || check.check_id.includes('CKV2_GCP')) {
      frameworks.push('GCP-CIS');
    }
    
    return frameworks.length > 0 ? frameworks : ['IaC-Best-Practices'];
  }

  private extractRemediationSteps(check: CheckovCheck): string[] {
    const steps: string[] = [];
    
    if (check.fixed_definition) {
      steps.push('Apply the fixed definition provided by Checkov');
    }
    
    if (check.guideline) {
      steps.push(check.guideline);
    }
    
    if (check.check_result.evaluated_keys.length > 0) {
      steps.push(`Review and fix the following keys: ${check.check_result.evaluated_keys.join(', ')}`);
    }
    
    return steps.length > 0 ? steps : ['Review the IaC configuration and apply security best practices'];
  }

  private extractReferences(check: CheckovCheck): string[] {
    const refs: string[] = [];
    
    if (check.bc_check_id) {
      refs.push(`https://www.bridgecrew.cloud/r/policy/${check.bc_check_id}`);
    }
    
    if (check.vulnerability_details?.cve_id) {
      refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${check.vulnerability_details.cve_id}`);
    }
    
    if (check.vulnerability_details?.cwe_id) {
      refs.push(`https://cwe.mitre.org/data/definitions/${check.vulnerability_details.cwe_id.replace('CWE-', '')}.html`);
    }
    
    refs.push(`https://www.checkov.io/5.Policy%20Index/${check.check_id}.html`);
    
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

