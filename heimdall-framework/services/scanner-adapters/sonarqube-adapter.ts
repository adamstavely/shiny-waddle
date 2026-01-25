/**
 * SonarQube SAST Adapter
 * 
 * Normalizes SonarQube issues to UnifiedFinding format
 */

import { BaseScannerAdapter, ScannerFinding } from './base-adapter';
import { UnifiedFinding } from '../../core/unified-finding-schema';

export interface SonarQubeIssue {
  key: string;
  rule: string;
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
  component: string;
  project: string;
  line?: number;
  message: string;
  type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL' | 'SECURITY_HOTSPOT';
  flows?: Array<{
    locations: Array<{
      component: string;
      textRange: {
        startLine: number;
        endLine: number;
        startOffset: number;
        endOffset: number;
      };
    }>;
  }>;
  textRange?: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  status?: string;
  resolution?: string;
  ruleDescription?: string;
  remediation?: {
    func?: string;
    message?: string;
  };
}

export class SonarQubeAdapter extends BaseScannerAdapter {
  constructor(config: any) {
    super({
      scannerId: 'sonarqube',
      source: 'sast',
      enabled: true,
      config,
    });
  }

  validate(finding: ScannerFinding): boolean {
    const issue = finding as SonarQubeIssue;
    return !!(
      issue.key &&
      issue.rule &&
      issue.severity &&
      issue.component &&
      issue.message
    );
  }

  normalize(finding: ScannerFinding, metadata?: Record<string, any>): UnifiedFinding {
    const issue = finding as SonarQubeIssue;
    const severity = this.extractSeverity(issue);
    const filePath = this.extractFilePath(issue.component);

    return {
      id: this.generateFindingId(issue.key),
      event: {
        kind: 'event',
        category: issue.type === 'VULNERABILITY' || issue.type === 'SECURITY_HOTSPOT' ? 'vulnerability' : 'security',
        type: 'vulnerability',
        action: 'detected',
        severity: this.mapSeverityToECS(severity),
      },
      source: 'sast',
      scannerId: 'sonarqube',
      scannerFindingId: issue.key,
      title: issue.message,
      description: issue.ruleDescription || issue.message,
      severity,
      confidence: 'firm',
      asset: {
        type: 'application',
        applicationId: metadata?.applicationId || issue.project,
        component: issue.component,
        location: {
          file: {
            name: filePath.name,
            path: filePath.path,
            extension: filePath.extension,
            directory: filePath.directory,
          },
          line: issue.line || issue.textRange?.startLine,
          column: issue.textRange?.startOffset,
        },
      },
      vulnerability: {
        id: issue.rule,
        classification: issue.rule,
        severity,
        scanner: {
          vendor: 'SonarSource',
          name: 'SonarQube',
          version: metadata?.sonarVersion,
        },
      },
      remediation: {
        description: issue.remediation?.message || '',
        steps: issue.remediation?.func ? [issue.remediation.func] : [],
        references: [`https://rules.sonarsource.com/${issue.rule}`],
        automated: false,
      },
      status: this.mapStatus(issue.status),
      createdAt: new Date(),
      updatedAt: new Date(),
      riskScore: this.calculateRiskScore(severity),
      raw: issue,
    };
  }

  protected extractSeverity(finding: ScannerFinding): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    const issue = finding as SonarQubeIssue;
    const mapping: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
      'BLOCKER': 'critical',
      'CRITICAL': 'high',
      'MAJOR': 'medium',
      'MINOR': 'low',
      'INFO': 'info',
    };
    return mapping[issue.severity] || 'medium';
  }

  private extractFilePath(component: string): {
    name: string;
    path: string;
    extension: string;
    directory: string;
  } {
    const parts = component.split(':');
    const filePath = parts[parts.length - 1] || component;
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

  private mapStatus(status?: string): 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted' {
    if (!status) return 'open';
    const mapping: Record<string, 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted'> = {
      'OPEN': 'open',
      'CONFIRMED': 'open',
      'REOPENED': 'open',
      'RESOLVED': 'resolved',
      'CLOSED': 'resolved',
      'FALSE-POSITIVE': 'false-positive',
      'WONTFIX': 'risk-accepted',
    };
    return mapping[status.toUpperCase()] || 'open';
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

