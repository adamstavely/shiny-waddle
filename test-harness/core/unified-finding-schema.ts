/**
 * Unified Security Finding Schema
 * 
 * Common data model for security findings from all scanners.
 * Compatible with Elastic Common Schema (ECS) for seamless integration.
 */

/**
 * Scanner source types
 */
export type ScannerSource = 
  | 'sast'           // Static Application Security Testing
  | 'dast'           // Dynamic Application Security Testing
  | 'sca'            // Software Composition Analysis
  | 'iac'            // Infrastructure as Code
  | 'container'      // Container scanning
  | 'cspm'           // Cloud Security Posture Management
  | 'secrets'        // Secrets scanning
  | 'api-security'   // API security testing
  | 'compliance';    // Compliance testing

/**
 * Scanner identifiers
 */
export type ScannerId =
  // SAST
  | 'sonarqube' | 'checkmarx' | 'veracode' | 'snyk-code' | 'semgrep' | 'codeql'
  // DAST
  | 'owasp-zap' | 'burp-suite' | 'acunetix' | 'nessus'
  // SCA
  | 'snyk' | 'whitesource' | 'mend' | 'dependabot' | 'github-security'
  // IaC
  | 'checkov' | 'terrascan' | 'snyk-iac' | 'bridgecrew'
  // Container
  | 'trivy' | 'snyk-container' | 'clair' | 'twistlock'
  // CSPM
  | 'aws-security-hub' | 'azure-security-center' | 'gcp-security-command-center'
  // Secrets
  | 'gitguardian' | 'trufflehog' | 'gitleaks'
  // API Security
  | '42crunch' | 'noname-security' | 'salt-security'
  // Compliance
  | 'sentinel-compliance';

/**
 * Unified Finding Schema
 * Maps to ECS fields where applicable
 */
export interface UnifiedFinding {
  // ECS: @timestamp (mapped from createdAt)
  id: string;
  
  // ECS: event.kind = "event", event.category = "security", event.type = "vulnerability"
  event: {
    kind: 'event';
    category: 'security' | 'vulnerability' | 'threat' | 'compliance';
    type: 'vulnerability' | 'finding' | 'alert' | 'compliance-violation';
    action: 'detected' | 'confirmed' | 'remediated' | 'accepted';
    severity: number; // ECS: event.severity (0-1000 scale, mapped from severity)
    original?: string; // Original event from scanner
  };
  
  // Scanner information
  source: ScannerSource;
  scannerId: ScannerId;
  scannerFindingId: string; // Original ID from scanner
  
  // ECS: vulnerability.* fields
  vulnerability?: {
    id?: string; // CVE ID
    cve?: {
      id?: string;
      description?: string;
      score?: {
        version?: string; // CVSS version
        base?: number;
        temporal?: number;
        environmental?: number;
        vector?: string;
      };
    };
    classification?: string; // CWE, OWASP category
    enumeration?: 'cve' | 'cwe' | 'ghsa' | 'osv';
    reference?: string;
    severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
    // ECS: vulnerability.scanner.*
    scanner?: {
      vendor: string;
      name: string;
      version?: string;
    };
  };
  
  // Core finding data
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'firm' | 'tentative';
  
  // ECS: host.* fields (for infrastructure/container findings)
  host?: {
    name?: string;
    id?: string;
    ip?: string[];
    mac?: string[];
    os?: {
      name?: string;
      version?: string;
      platform?: string;
    };
    container?: {
      id?: string;
      name?: string;
      image?: {
        name?: string;
        tag?: string;
      };
    };
  };
  
  // Asset context
  asset: {
    type: 'application' | 'infrastructure' | 'dependency' | 'container' | 'iac' | 'api';
    applicationId?: string;
    component?: string; // File, endpoint, resource, etc.
    location?: {
      // ECS: file.* fields
      file?: {
        name?: string;
        path?: string;
        extension?: string;
        directory?: string;
        size?: number;
        code_signature?: {
          subject_name?: string;
          valid?: boolean;
        };
      };
      line?: number;
      column?: number;
      // ECS: url.* fields for endpoints
      url?: {
        original?: string;
        scheme?: string;
        domain?: string;
        port?: number;
        path?: string;
        query?: string;
        fragment?: string;
      };
      resource?: string; // Cloud resource ARN/ID
      region?: string; // Cloud region
    };
  };
  
  // ECS: threat.* fields
  threat?: {
    framework?: string; // MITRE ATT&CK, OWASP, etc.
    tactic?: {
      id?: string;
      name?: string;
      reference?: string;
    };
    technique?: {
      id?: string;
      name?: string;
      reference?: string;
    };
  };
  
  // Compliance mapping
  compliance?: {
    frameworks: string[]; // SOC2, PCI-DSS, HIPAA, GDPR, etc.
    controls: string[];
    requirements: string[];
    // ECS: rule.* fields for compliance rules
    rule?: {
      id?: string;
      name?: string;
      category?: string;
      description?: string;
    };
  };
  
  // Remediation
  remediation: {
    description: string;
    steps: string[];
    references: string[];
    estimatedEffort?: 'low' | 'medium' | 'high';
    automated?: boolean;
    // ECS: related.* for remediation tracking
    related?: {
      type?: string;
      id?: string;
    };
  };
  
  // Lifecycle
  status: 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted';
  assignedTo?: string;
  
  // ECS: @timestamp fields
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  detectedAt?: Date; // When scanner detected it
  
  // Risk scoring
  riskScore: number; // 0-100, calculated based on severity, exploitability, asset criticality
  businessImpact?: number; // 0-100
  
  // Enhanced risk scoring (from enhanced-risk-scorer)
  enhancedRiskScore?: {
    baseScore: number;
    adjustedScore: number;
    factors: {
      severity: number;
      exploitability: number;
      assetCriticality: number;
      exposure: number;
      dataSensitivity: number;
      complianceImpact: number;
      businessImpact: number;
      remediationComplexity: number;
    };
    age: number; // Days since detection
    trend: 'increasing' | 'stable' | 'decreasing';
    threatIntelligence?: {
      activeExploits: boolean;
      exploitInWild: boolean;
      ransomware: boolean;
      threatActorInterest: 'high' | 'medium' | 'low';
    };
    priority: number; // 0-100
    priorityReason: string;
    calculatedAt: Date;
    version: string;
  };
  
  // Correlation
  relatedFindings?: string[]; // IDs of related findings
  duplicateOf?: string; // If this is a duplicate
  
  // ECS: organization.* fields
  organization?: {
    id?: string;
    name?: string;
  };
  
  // ECS: user.* fields (for user-related findings)
  user?: {
    id?: string;
    name?: string;
    email?: string;
    roles?: string[];
  };
  
  // ECS: process.* fields (for runtime findings)
  process?: {
    name?: string;
    pid?: number;
    command_line?: string;
    executable?: string;
  };
  
  // ECS: network.* fields (for network-related findings)
  network?: {
    protocol?: string;
    direction?: 'inbound' | 'outbound';
    transport?: 'tcp' | 'udp';
  };
  
  // Custom fields for Heimdall-specific data
  heimdall?: {
    testSuiteId?: string;
    testResultId?: string;
    policyId?: string;
    policyName?: string;
    violationId?: string;
  };
  
  // Legacy: Keep sentinel for backward compatibility
  sentinel?: {
    testSuiteId?: string;
    testResultId?: string;
    policyId?: string;
    policyName?: string;
    violationId?: string;
  };
  
  // Raw scanner data (for debugging/audit)
  raw?: Record<string, any>;
}

/**
 * ECS-compatible document structure
 * Maps UnifiedFinding to ECS format for Elasticsearch ingestion
 */
export interface ECSDocument {
  '@timestamp': string; // ISO 8601 timestamp
  'event.kind': 'event';
  'event.category': string[];
  'event.type': string[];
  'event.action': string;
  'event.severity': number;
  'event.original'?: string;
  
  'vulnerability.id'?: string;
  'vulnerability.cve.id'?: string;
  'vulnerability.cve.description'?: string;
  'vulnerability.cve.score.base'?: number;
  'vulnerability.cve.score.version'?: string;
  'vulnerability.cve.score.vector'?: string;
  'vulnerability.classification'?: string;
  'vulnerability.severity'?: string;
  'vulnerability.scanner.vendor'?: string;
  'vulnerability.scanner.name'?: string;
  
  'host.name'?: string;
  'host.id'?: string;
  'host.ip'?: string[];
  'host.os.name'?: string;
  'host.os.version'?: string;
  'host.container.id'?: string;
  'host.container.image.name'?: string;
  
  'file.name'?: string;
  'file.path'?: string;
  'file.extension'?: string;
  'file.directory'?: string;
  'file.code_signature.subject_name'?: string;
  
  'url.original'?: string;
  'url.scheme'?: string;
  'url.domain'?: string;
  'url.path'?: string;
  
  'threat.framework'?: string;
  'threat.tactic.id'?: string;
  'threat.tactic.name'?: string;
  'threat.technique.id'?: string;
  'threat.technique.name'?: string;
  
  'rule.id'?: string;
  'rule.name'?: string;
  'rule.category'?: string;
  
  'user.id'?: string;
  'user.name'?: string;
  'user.email'?: string;
  
  'process.name'?: string;
  'process.pid'?: number;
  'process.command_line'?: string;
  
  'network.protocol'?: string;
  'network.direction'?: string;
  'network.transport'?: string;
  
  'organization.id'?: string;
  'organization.name'?: string;
  
  // Custom fields (prefixed with heimdall.*)
  'heimdall.finding.id'?: string;
  'heimdall.scanner.source'?: string;
  'heimdall.scanner.id'?: string;
  'heimdall.scanner.finding_id'?: string;
  'heimdall.asset.type'?: string;
  'heimdall.asset.application_id'?: string;
  'heimdall.asset.component'?: string;
  'heimdall.status'?: string;
  'heimdall.risk_score'?: number;
  'heimdall.business_impact'?: number;
  'heimdall.remediation.automated'?: boolean;
  'heimdall.compliance.frameworks'?: string[];
  'heimdall.compliance.controls'?: string[];
  
  // Legacy: Keep sentinel.* for backward compatibility
  'sentinel.finding.id'?: string;
  'sentinel.scanner.source'?: string;
  'sentinel.scanner.id'?: string;
  'sentinel.scanner.finding_id'?: string;
  'sentinel.asset.type'?: string;
  'sentinel.asset.application_id'?: string;
  'sentinel.asset.component'?: string;
  'sentinel.status'?: string;
  'sentinel.risk_score'?: number;
  'sentinel.business_impact'?: number;
  'sentinel.remediation.automated'?: boolean;
  'sentinel.compliance.frameworks'?: string[];
  'sentinel.compliance.controls'?: string[];
  
  // Additional metadata
  'message'?: string; // Human-readable message
  'tags'?: string[];
  'labels'?: Record<string, string>;
}

