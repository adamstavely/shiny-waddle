export type ScannerSource = 'sast' | 'dast' | 'sca' | 'iac' | 'container' | 'cspm' | 'secrets' | 'api-security' | 'compliance';
export type ScannerId = 'sonarqube' | 'checkmarx' | 'veracode' | 'snyk-code' | 'semgrep' | 'codeql' | 'owasp-zap' | 'burp-suite' | 'acunetix' | 'nessus' | 'snyk' | 'whitesource' | 'mend' | 'dependabot' | 'github-security' | 'sonatype-iq' | 'checkov' | 'terrascan' | 'snyk-iac' | 'bridgecrew' | 'trivy' | 'snyk-container' | 'clair' | 'twistlock' | 'aws-security-hub' | 'azure-security-center' | 'gcp-security-command-center' | 'gitguardian' | 'trufflehog' | 'gitleaks' | '42crunch' | 'noname-security' | 'salt-security' | 'sentinel-compliance';
export interface UnifiedFinding {
    id: string;
    event: {
        kind: 'event';
        category: 'security' | 'vulnerability' | 'threat' | 'compliance';
        type: 'vulnerability' | 'finding' | 'alert' | 'compliance-violation';
        action: 'detected' | 'confirmed' | 'remediated' | 'accepted';
        severity: number;
        original?: string;
    };
    source: ScannerSource;
    scannerId: ScannerId;
    scannerFindingId: string;
    vulnerability?: {
        id?: string;
        cve?: {
            id?: string;
            description?: string;
            score?: {
                version?: string;
                base?: number;
                temporal?: number;
                environmental?: number;
                vector?: string;
            };
        };
        classification?: string;
        enumeration?: 'cve' | 'cwe' | 'ghsa' | 'osv';
        reference?: string;
        severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
        scanner?: {
            vendor: string;
            name: string;
            version?: string;
        };
    };
    title: string;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    confidence: 'confirmed' | 'firm' | 'tentative';
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
    asset: {
        type: 'application' | 'infrastructure' | 'dependency' | 'container' | 'iac' | 'api';
        applicationId?: string;
        component?: string;
        location?: {
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
            url?: {
                original?: string;
                scheme?: string;
                domain?: string;
                port?: number;
                path?: string;
                query?: string;
                fragment?: string;
            };
            resource?: string;
            region?: string;
        };
    };
    threat?: {
        framework?: string;
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
    compliance?: {
        frameworks: string[];
        controls: string[];
        requirements: string[];
        rule?: {
            id?: string;
            name?: string;
            category?: string;
            description?: string;
        };
    };
    remediation: {
        description: string;
        steps: string[];
        references: string[];
        estimatedEffort?: 'low' | 'medium' | 'high';
        automated?: boolean;
        related?: {
            type?: string;
            id?: string;
        };
    };
    status: 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted';
    assignedTo?: string;
    createdAt: Date;
    updatedAt: Date;
    resolvedAt?: Date;
    detectedAt?: Date;
    riskScore: number;
    businessImpact?: number;
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
        age: number;
        trend: 'increasing' | 'stable' | 'decreasing';
        threatIntelligence?: {
            activeExploits: boolean;
            exploitInWild: boolean;
            ransomware: boolean;
            threatActorInterest: 'high' | 'medium' | 'low';
        };
        priority: number;
        priorityReason: string;
        calculatedAt: Date;
        version: string;
    };
    relatedFindings?: string[];
    duplicateOf?: string;
    organization?: {
        id?: string;
        name?: string;
    };
    user?: {
        id?: string;
        name?: string;
        email?: string;
        roles?: string[];
    };
    process?: {
        name?: string;
        pid?: number;
        command_line?: string;
        executable?: string;
    };
    network?: {
        protocol?: string;
        direction?: 'inbound' | 'outbound';
        transport?: 'tcp' | 'udp';
    };
    heimdall?: {
        testSuiteId?: string;
        testResultId?: string;
        policyId?: string;
        policyName?: string;
        violationId?: string;
    };
    raw?: Record<string, any>;
}
export interface ECSDocument {
    '@timestamp': string;
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
    'message'?: string;
    'tags'?: string[];
    'labels'?: Record<string, string>;
}
