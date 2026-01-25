/**
 * ECS Adapter Service
 * 
 * Converts UnifiedFinding to Elastic Common Schema (ECS) format
 * for seamless integration with Elasticsearch and ECS-compatible tools
 */

import { UnifiedFinding, ECSDocument } from '../core/unified-finding-schema';

export class ECSAdapter {
  /**
   * Convert UnifiedFinding to ECS document format
   */
  toECS(finding: UnifiedFinding): ECSDocument {
    const doc: ECSDocument = {
      '@timestamp': finding.detectedAt?.toISOString() || finding.createdAt.toISOString(),
      'event.kind': 'event',
      'event.category': [finding.event.category],
      'event.type': [finding.event.type],
      'event.action': finding.event.action,
      'event.severity': this.mapSeverityToECS(finding.severity),
      'event.original': finding.event.original,
      
      // Heimdall custom fields
      'heimdall.finding.id': finding.id,
      'heimdall.scanner.source': finding.source,
      'heimdall.scanner.id': finding.scannerId,
      'heimdall.scanner.finding_id': finding.scannerFindingId,
      'heimdall.asset.type': finding.asset.type,
      'heimdall.asset.application_id': finding.asset.applicationId,
      'heimdall.asset.component': finding.asset.component,
      'heimdall.status': finding.status,
      'heimdall.risk_score': finding.riskScore,
      'heimdall.business_impact': finding.businessImpact,
      'heimdall.remediation.automated': finding.remediation.automated,
      
      // Message
      'message': finding.title,
      'tags': this.generateTags(finding),
    };

    // Vulnerability fields
    if (finding.vulnerability) {
      doc['vulnerability.id'] = finding.vulnerability.id || finding.vulnerability.cve?.id;
      doc['vulnerability.severity'] = finding.vulnerability.severity || finding.severity;
      
      if (finding.vulnerability.cve) {
        doc['vulnerability.cve.id'] = finding.vulnerability.cve.id;
        doc['vulnerability.cve.description'] = finding.vulnerability.cve.description;
        if (finding.vulnerability.cve.score) {
          doc['vulnerability.cve.score.base'] = finding.vulnerability.cve.score.base;
          doc['vulnerability.cve.score.version'] = finding.vulnerability.cve.score.version;
          doc['vulnerability.cve.score.vector'] = finding.vulnerability.cve.score.vector;
        }
      }
      
      if (finding.vulnerability.classification) {
        doc['vulnerability.classification'] = finding.vulnerability.classification;
      }
      
      if (finding.vulnerability.scanner) {
        doc['vulnerability.scanner.vendor'] = finding.vulnerability.scanner.vendor;
        doc['vulnerability.scanner.name'] = finding.vulnerability.scanner.name;
        if (finding.vulnerability.scanner.version) {
          doc['vulnerability.scanner.version'] = finding.vulnerability.scanner.version;
        }
      }
    }

    // Host fields
    if (finding.host) {
      if (finding.host.name) doc['host.name'] = finding.host.name;
      if (finding.host.id) doc['host.id'] = finding.host.id;
      if (finding.host.ip) doc['host.ip'] = finding.host.ip;
      if (finding.host.os) {
        if (finding.host.os.name) doc['host.os.name'] = finding.host.os.name;
        if (finding.host.os.version) doc['host.os.version'] = finding.host.os.version;
        if (finding.host.os.platform) doc['host.os.platform'] = finding.host.os.platform;
      }
      if (finding.host.container) {
        if (finding.host.container.id) doc['host.container.id'] = finding.host.container.id;
        if (finding.host.container.name) doc['host.container.name'] = finding.host.container.name;
        if (finding.host.container.image) {
          if (finding.host.container.image.name) {
            doc['host.container.image.name'] = finding.host.container.image.name;
          }
          if (finding.host.container.image.tag) {
            doc['host.container.image.tag'] = finding.host.container.image.tag;
          }
        }
      }
    }

    // File fields
    if (finding.asset.location?.file) {
      const file = finding.asset.location.file;
      if (file.name) doc['file.name'] = file.name;
      if (file.path) doc['file.path'] = file.path;
      if (file.extension) doc['file.extension'] = file.extension;
      if (file.directory) doc['file.directory'] = file.directory;
      if (file.size) doc['file.size'] = file.size;
      if (file.code_signature) {
        if (file.code_signature.subject_name) {
          doc['file.code_signature.subject_name'] = file.code_signature.subject_name;
        }
        if (file.code_signature.valid !== undefined) {
          doc['file.code_signature.valid'] = file.code_signature.valid;
        }
      }
    }

    // URL fields
    if (finding.asset.location?.url) {
      const url = finding.asset.location.url;
      if (url.original) doc['url.original'] = url.original;
      if (url.scheme) doc['url.scheme'] = url.scheme;
      if (url.domain) doc['url.domain'] = url.domain;
      if (url.port) doc['url.port'] = url.port;
      if (url.path) doc['url.path'] = url.path;
      if (url.query) doc['url.query'] = url.query;
      if (url.fragment) doc['url.fragment'] = url.fragment;
    }

    // Threat fields
    if (finding.threat) {
      if (finding.threat.framework) doc['threat.framework'] = finding.threat.framework;
      if (finding.threat.tactic) {
        if (finding.threat.tactic.id) doc['threat.tactic.id'] = finding.threat.tactic.id;
        if (finding.threat.tactic.name) doc['threat.tactic.name'] = finding.threat.tactic.name;
        if (finding.threat.tactic.reference) doc['threat.tactic.reference'] = finding.threat.tactic.reference;
      }
      if (finding.threat.technique) {
        if (finding.threat.technique.id) doc['threat.technique.id'] = finding.threat.technique.id;
        if (finding.threat.technique.name) doc['threat.technique.name'] = finding.threat.technique.name;
        if (finding.threat.technique.reference) doc['threat.technique.reference'] = finding.threat.technique.reference;
      }
    }

    // Compliance/rule fields
    if (finding.compliance) {
      doc['heimdall.compliance.frameworks'] = finding.compliance.frameworks;
      doc['heimdall.compliance.controls'] = finding.compliance.controls;
      
      if (finding.compliance.rule) {
        if (finding.compliance.rule.id) doc['rule.id'] = finding.compliance.rule.id;
        if (finding.compliance.rule.name) doc['rule.name'] = finding.compliance.rule.name;
        if (finding.compliance.rule.category) doc['rule.category'] = finding.compliance.rule.category;
        if (finding.compliance.rule.description) doc['rule.description'] = finding.compliance.rule.description;
      }
    }

    // User fields
    if (finding.user) {
      if (finding.user.id) doc['user.id'] = finding.user.id;
      if (finding.user.name) doc['user.name'] = finding.user.name;
      if (finding.user.email) doc['user.email'] = finding.user.email;
      if (finding.user.roles) doc['user.roles'] = finding.user.roles;
    }

    // Process fields
    if (finding.process) {
      if (finding.process.name) doc['process.name'] = finding.process.name;
      if (finding.process.pid) doc['process.pid'] = finding.process.pid;
      if (finding.process.command_line) doc['process.command_line'] = finding.process.command_line;
      if (finding.process.executable) doc['process.executable'] = finding.process.executable;
    }

    // Network fields
    if (finding.network) {
      if (finding.network.protocol) doc['network.protocol'] = finding.network.protocol;
      if (finding.network.direction) doc['network.direction'] = finding.network.direction;
      if (finding.network.transport) doc['network.transport'] = finding.network.transport;
    }

    // Organization fields
    if (finding.organization) {
      if (finding.organization.id) doc['organization.id'] = finding.organization.id;
      if (finding.organization.name) doc['organization.name'] = finding.organization.name;
    }

    // Labels
    doc['labels'] = {
      scanner: finding.scannerId,
      source: finding.source,
      severity: finding.severity,
      status: finding.status,
      assetType: finding.asset.type,
    };

    return doc;
  }

  /**
   * Convert ECS document back to UnifiedFinding
   */
  fromECS(doc: ECSDocument): UnifiedFinding {
    const finding: UnifiedFinding = {
      id: doc['heimdall.finding.id'] || doc['vulnerability.id'] || `ecs-${Date.now()}`,
      event: {
        kind: 'event',
        category: (doc['event.category']?.[0] as any) || 'security',
        type: (doc['event.type']?.[0] as any) || 'vulnerability',
        action: (doc['event.action'] as 'detected' | 'confirmed' | 'remediated' | 'accepted') || 'detected',
        severity: doc['event.severity'] || 0,
        original: doc['event.original'],
      },
      source: (doc['heimdall.scanner.source'] as any) || 'compliance',
      scannerId: (doc['heimdall.scanner.id'] as any) || 'heimdall-compliance',
      scannerFindingId: doc['heimdall.scanner.finding_id'] || doc['vulnerability.id'] || '',
      title: doc['message'] || 'Security Finding',
      description: doc['vulnerability.cve.description'] || '',
      severity: this.mapECSSeverity(doc['vulnerability.severity'] || doc['event.severity']),
      confidence: 'firm',
      asset: {
        type: (doc['heimdall.asset.type'] as any) || 'application',
        applicationId: doc['heimdall.asset.application_id'],
        component: doc['heimdall.asset.component'],
        location: {
          file: doc['file.name'] ? {
            name: doc['file.name'],
            path: doc['file.path'],
            extension: doc['file.extension'],
            directory: doc['file.directory'],
            size: doc['file.size'],
          } : undefined,
          url: doc['url.original'] ? {
            original: doc['url.original'],
            scheme: doc['url.scheme'],
            domain: doc['url.domain'],
            port: doc['url.port'],
            path: doc['url.path'],
            query: doc['url.query'],
            fragment: doc['url.fragment'],
          } : undefined,
        },
      },
      remediation: {
        description: '',
        steps: [],
        references: [],
        automated: doc['heimdall.remediation.automated'],
      },
      status: (doc['heimdall.status'] as any) || 'open',
      createdAt: new Date(doc['@timestamp']),
      updatedAt: new Date(doc['@timestamp']),
      riskScore: doc['heimdall.risk_score'] || 0,
      businessImpact: doc['heimdall.business_impact'],
    };

    if (doc['vulnerability.id'] || doc['vulnerability.cve.id']) {
      finding.vulnerability = {
        id: doc['vulnerability.id'] || doc['vulnerability.cve.id'],
        severity: (doc['vulnerability.severity'] as any) || finding.severity,
        cve: doc['vulnerability.cve.id'] ? {
          id: doc['vulnerability.cve.id'],
          description: doc['vulnerability.cve.description'],
          score: doc['vulnerability.cve.score.base'] ? {
            base: doc['vulnerability.cve.score.base'],
            version: doc['vulnerability.cve.score.version'],
            vector: doc['vulnerability.cve.score.vector'],
          } : undefined,
        } : undefined,
        classification: doc['vulnerability.classification'],
        scanner: doc['vulnerability.scanner.vendor'] ? {
          vendor: doc['vulnerability.scanner.vendor'],
          name: doc['vulnerability.scanner.name'],
          version: doc['vulnerability.scanner.version'],
        } : undefined,
      };
    }

    if (doc['host.name'] || doc['host.container.id']) {
      finding.host = {
        name: doc['host.name'],
        id: doc['host.id'],
        ip: doc['host.ip'],
        os: doc['host.os.name'] ? {
          name: doc['host.os.name'],
          version: doc['host.os.version'],
          platform: doc['host.os.platform'],
        } : undefined,
        container: doc['host.container.id'] ? {
          id: doc['host.container.id'],
          name: doc['host.container.name'],
          image: doc['host.container.image.name'] ? {
            name: doc['host.container.image.name'],
            tag: doc['host.container.image.tag'],
          } : undefined,
        } : undefined,
      };
    }

    if (doc['compliance.frameworks'] || doc['heimdall.compliance.frameworks']) {
      finding.compliance = {
        frameworks: doc['heimdall.compliance.frameworks'] || [],
        controls: doc['heimdall.compliance.controls'] || [],
        requirements: [],
        rule: doc['rule.id'] ? {
          id: doc['rule.id'],
          name: doc['rule.name'],
          category: doc['rule.category'],
          description: doc['rule.description'],
        } : undefined,
      };
    }

    return finding;
  }

  /**
   * Map severity to ECS severity scale (0-1000)
   * ECS uses 0-1000 scale where 0=lowest, 1000=highest
   */
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

  /**
   * Map ECS severity back to string
   */
  private mapECSSeverity(severity: number | string | undefined): 'critical' | 'high' | 'medium' | 'low' | 'info' {
    if (typeof severity === 'string') {
      return severity as any;
    }
    if (typeof severity === 'number') {
      if (severity >= 750) return 'critical';
      if (severity >= 500) return 'high';
      if (severity >= 250) return 'medium';
      if (severity >= 100) return 'low';
      return 'info';
    }
    return 'medium';
  }

  /**
   * Generate tags for ECS document
   */
  private generateTags(finding: UnifiedFinding): string[] {
    const tags: string[] = [
      `scanner:${finding.scannerId}`,
      `source:${finding.source}`,
      `severity:${finding.severity}`,
      `status:${finding.status}`,
      `asset-type:${finding.asset.type}`,
    ];

    if (finding.vulnerability?.cve?.id) {
      tags.push(`cve:${finding.vulnerability.cve.id}`);
    }
    if (finding.compliance?.frameworks) {
      finding.compliance.frameworks.forEach(fw => tags.push(`framework:${fw.toLowerCase()}`));
    }
    if (finding.asset.applicationId) {
      tags.push(`application:${finding.asset.applicationId}`);
    }

    return tags;
  }

  /**
   * Batch convert findings to ECS documents
   */
  batchToECS(findings: UnifiedFinding[]): ECSDocument[] {
    return findings.map(f => this.toECS(f));
  }

  /**
   * Batch convert ECS documents to findings
   */
  batchFromECS(docs: ECSDocument[]): UnifiedFinding[] {
    return docs.map(d => this.fromECS(d));
  }
}

