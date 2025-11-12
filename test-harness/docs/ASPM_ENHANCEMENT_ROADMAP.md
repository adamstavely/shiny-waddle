# ASPM Enhancement Roadmap

This document outlines the key capabilities needed to transform Sentinel into a robust, production-ready Application Security Posture Management (ASPM) platform, assuming integration with various security scanners.

## Current State Assessment

### ✅ What We Have
- Policy management and testing framework
- Basic integrations (SAST, DAST, DBT, Great Expectations)
- Test execution and results tracking
- Violations management
- Basic analytics and reporting
- CI/CD integration hooks
- API security testing
- **Unified Security Data Model & Normalization** ✅
  - ECS-compatible unified finding schema
  - 6 scanner adapters (SonarQube, Snyk, OWASP ZAP, Checkov, Trivy, AWS Security Hub)
  - Normalization engine with deduplication and enrichment
  - Backend API for findings management
  - Frontend UI for unified findings view

### ❌ Critical Gaps for Production ASPM

---

## 1. Unified Security Data Model & Normalization

### Status: ✅ **COMPLETED**

### Problem
Different scanners produce findings in different formats. We need a unified data model to aggregate, correlate, and analyze findings across all sources.

### Implementation Summary
- ✅ **Common Finding Schema**: Implemented with full ECS (Elastic Common Schema) compatibility
- ✅ **ECS Adapter**: Bidirectional conversion between UnifiedFinding and ECS format
- ✅ **Scanner Adapters**: 6 adapters implemented (SonarQube, Snyk SCA/Container, OWASP ZAP, Checkov, Trivy, AWS Security Hub)
- ✅ **Normalization Engine**: Full normalization with deduplication, enrichment, and validation
- ✅ **Backend API**: Complete REST API for findings management and ECS export
- ✅ **Frontend UI**: Unified findings dashboard with import, filtering, and ECS export

### Required Components

#### 1.1 Common Finding Schema ✅ **IMPLEMENTED**
```typescript
interface UnifiedFinding {
  id: string;
  source: ScannerSource; // SAST, DAST, SCA, IaC, CSPM, etc.
  scannerId: string; // SonarQube, Snyk, Checkmarx, etc.
  scannerFindingId: string; // Original ID from scanner
  
  // Core finding data
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'firm' | 'tentative';
  
  // Asset context
  asset: {
    type: 'application' | 'infrastructure' | 'dependency' | 'container' | 'iac';
    applicationId?: string;
    component?: string; // File, endpoint, resource, etc.
    location?: {
      file?: string;
      line?: number;
      endpoint?: string;
      resource?: string;
    };
  };
  
  // Vulnerability data
  vulnerability?: {
    cveId?: string;
    cweId?: string;
    owaspCategory?: string;
    exploitability?: 'exploitable' | 'potentially-exploitable' | 'not-exploitable';
    cvssScore?: number;
    cvssVector?: string;
  };
  
  // Compliance mapping
  compliance?: {
    frameworks: string[]; // SOC2, PCI-DSS, HIPAA, etc.
    controls: string[];
    requirements: string[];
  };
  
  // Remediation
  remediation: {
    description: string;
    steps: string[];
    references: string[];
    estimatedEffort?: 'low' | 'medium' | 'high';
    automated?: boolean;
  };
  
  // Lifecycle
  status: 'open' | 'in-progress' | 'resolved' | 'false-positive' | 'risk-accepted';
  assignedTo?: string;
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  
  // Risk scoring
  riskScore: number; // Calculated based on severity, exploitability, asset criticality
  businessImpact?: number;
  
  // Correlation
  relatedFindings?: string[]; // IDs of related findings
  duplicateOf?: string; // If this is a duplicate
}
```

#### 1.2 Scanner Adapters ✅ **PARTIALLY IMPLEMENTED**
**Implemented:**
- ✅ **SAST**: SonarQube
- ✅ **DAST**: OWASP ZAP
- ✅ **SCA**: Snyk (SCA and Container)
- ✅ **IaC**: Checkov
- ✅ **Container**: Trivy, Snyk Container
- ✅ **CSPM**: AWS Security Hub

**Remaining:**
- **SAST Adapters**: Checkmarx, Veracode, Snyk Code, Semgrep, CodeQL
- **DAST Adapters**: Burp Suite, Acunetix, Nessus
- **SCA Adapters**: WhiteSource, Mend, Dependabot, GitHub Security
- **IaC Scanners**: Terrascan, Snyk IaC, Bridgecrew
- **Container Scanners**: Clair, Twistlock
- **CSPM Adapters**: Azure Security Center, GCP Security Command Center
- **Secrets Scanners**: GitGuardian, TruffleHog, GitLeaks
- **API Security**: 42Crunch, Noname Security, Salt Security

**Implementation Details:**
- Base adapter class (`BaseScannerAdapter`) provides common functionality
- Each adapter implements `normalize()` and `validate()` methods
- Support for single or multiple findings per scanner result
- Automatic risk score calculation
- CVE/CWE extraction and mapping
- Remediation step extraction

#### 1.3 Normalization Engine ✅ **IMPLEMENTED**
- ✅ Convert scanner-specific formats to unified schema
- ✅ Validate and enrich findings data
- ✅ De-duplicate findings across scanners (exact and fuzzy matching)
- ✅ ECS format conversion for Elasticsearch integration
- ✅ Batch normalization support
- ✅ Configurable deduplication strategies
- ✅ Automatic compliance framework mapping
- ⏳ Schema versioning and migration (planned)

**Implementation Details:**
- Location: `services/normalization-engine.ts`
- Deduplication strategies: exact (same CVE/rule on same asset) and fuzzy (similarity-based)
- Enrichment: CVE/CWE data, compliance framework mapping
- Validation: Strict and non-strict modes
- ECS Integration: Full bidirectional conversion via `ECSAdapter`

---

## 2. Asset Inventory & Discovery

### Problem
ASPM needs comprehensive visibility into all assets (applications, infrastructure, dependencies) to properly contextualize findings.

### Required Components

#### 2.1 Asset Registry
```typescript
interface Asset {
  id: string;
  type: 'application' | 'service' | 'infrastructure' | 'dependency' | 'container';
  name: string;
  description?: string;
  
  // Ownership
  team: string;
  owner: string;
  tags: string[];
  
  // Criticality
  criticality: 'critical' | 'high' | 'medium' | 'low';
  businessImpact: string;
  dataClassification?: 'public' | 'internal' | 'confidential' | 'restricted';
  
  // Technical details
  technology: {
    language?: string;
    framework?: string;
    runtime?: string;
    platform?: string;
  };
  
  // Location
  repository?: {
    url: string;
    branch: string;
  };
  deployment?: {
    environment: string;
    region: string;
    cluster?: string;
  };
  
  // Dependencies
  dependencies?: {
    direct: Dependency[];
    transitive: Dependency[];
  };
  
  // Relationships
  dependsOn?: string[]; // Asset IDs
  usedBy?: string[]; // Asset IDs
  
  // Metadata
  createdAt: Date;
  updatedAt: Date;
  lastScanned?: Date;
}
```

#### 2.2 Discovery Mechanisms
- **Repository Scanning**: Auto-discover applications from Git repos
- **CI/CD Integration**: Discover assets from build pipelines
- **Cloud Provider APIs**: Discover infrastructure from AWS/Azure/GCP
- **Container Registry Scanning**: Discover container images
- **Dependency Scanning**: Discover dependencies from package managers
- **Service Mesh Integration**: Discover services from Istio/Linkerd

#### 2.3 Asset Relationship Mapping
- Dependency graphs
- Service dependency maps
- Infrastructure topology
- Data flow diagrams

---

## 3. Risk Scoring & Prioritization

### Problem
Not all findings are equal. Need intelligent risk scoring that considers multiple factors.

### Required Components

#### 3.1 Context-Aware Risk Scoring
```typescript
interface RiskScore {
  baseScore: number; // From CVSS or scanner
  adjustedScore: number; // After context adjustment
  
  factors: {
    severity: number;
    exploitability: number;
    assetCriticality: number;
    exposure: number; // Public-facing, internal-only, etc.
    dataSensitivity: number;
    complianceImpact: number;
    businessImpact: number;
    remediationComplexity: number;
  };
  
  // Temporal factors
  age: number; // How long has this been open?
  trend: 'increasing' | 'stable' | 'decreasing';
  
  // Threat intelligence
  threatIntelligence?: {
    activeExploits: boolean;
    exploitInWild: boolean;
    ransomware: boolean;
    threatActorInterest: 'high' | 'medium' | 'low';
  };
}
```

#### 3.2 Prioritization Engine
- ML-based prioritization
- Business context integration
- Exploitability assessment
- Remediation effort vs. risk trade-off
- SLA-based prioritization

#### 3.3 Risk Aggregation
- Application-level risk scores
- Team-level risk scores
- Organization-level risk scores
- Risk trends over time

---

## 4. Vulnerability Management

### Problem
Need comprehensive vulnerability lifecycle management beyond basic tracking.

### Required Components

#### 4.1 CVE Intelligence Integration
- CVE database integration (NVD, MITRE)
- CWE mapping
- OWASP Top 10 mapping
- Exploitability data (Exploit-DB, Metasploit)
- Patch availability tracking

#### 4.2 Vulnerability Lifecycle
- Discovery → Triage → Assignment → Remediation → Verification → Closure
- SLA tracking per severity
- Escalation workflows
- Risk acceptance workflows

#### 4.3 False Positive Management
- ML-based false positive detection
- Historical false positive patterns
- User feedback loop
- Auto-suppression rules

#### 4.4 Patch Management
- Patch availability tracking
- Patch testing workflows
- Rollback capabilities
- Emergency patching procedures

---

## 5. Compliance & Governance

### Problem
ASPM must demonstrate compliance with various frameworks and regulations.

### Required Components

#### 5.1 Compliance Framework Mapping
- **SOC 2**: Type I/II controls mapping
- **PCI-DSS**: Requirements mapping
- **HIPAA**: Safeguards mapping
- **GDPR**: Article mapping
- **ISO 27001**: Control mapping
- **NIST CSF**: Framework mapping
- **OWASP ASVS**: Verification mapping

#### 5.2 Compliance Dashboard
- Framework coverage percentage
- Control compliance status
- Gap analysis
- Remediation roadmap

#### 5.3 Policy as Code
- Policy definition in code (YAML/JSON)
- Policy versioning
- Policy testing
- Policy enforcement

#### 5.4 Audit & Evidence
- Audit trail of all changes
- Evidence collection
- Compliance reports
- Attestation workflows

---

## 6. Threat Intelligence Integration

### Problem
Static vulnerability data isn't enough. Need real-time threat intelligence.

### Required Components

#### 6.1 Threat Intelligence Sources
- CVE feeds (NVD, MITRE)
- Exploit intelligence (Exploit-DB, Metasploit)
- Threat actor intelligence
- Industry-specific threat feeds
- Custom threat feeds

#### 6.2 Threat Correlation
- Map findings to known exploits
- Identify active campaigns
- Track threat actor TTPs
- Industry benchmark comparison

#### 6.3 Threat-Aware Prioritization
- Boost priority for actively exploited vulnerabilities
- Alert on emerging threats
- Threat landscape visualization

---

## 7. Remediation & Workflow Management

### Problem
Findings need to be assigned, tracked, and remediated efficiently.

### Required Components

#### 7.1 Ticketing Integration
- Jira integration
- ServiceNow integration
- GitHub Issues integration
- Custom ticketing systems

#### 7.2 Remediation Workflows
- Assignment rules
- Escalation policies
- SLA management
- Approval workflows

#### 7.3 Automated Remediation
- Auto-fix capabilities (where safe)
- Pull request generation
- Patch application automation
- Configuration change automation

#### 7.4 Remediation Tracking
- Progress tracking
- Time-to-remediation metrics
- Remediation effectiveness
- Recurrence tracking

---

## 8. Advanced Analytics & Reporting

### Problem
Need deeper insights beyond basic dashboards.

### Required Components

#### 8.1 Executive Dashboards
- Security posture overview
- Risk trends
- Compliance status
- Remediation velocity
- ROI metrics

#### 8.2 Trend Analysis
- Finding trends over time
- Risk trend analysis
- Compliance trend analysis
- Remediation velocity trends

#### 8.3 Predictive Analytics
- Risk prediction models
- Vulnerability prediction
- Compliance drift prediction
- Resource needs prediction

#### 8.4 Custom Reports
- Configurable report builder
- Scheduled reports
- Export formats (PDF, Excel, JSON)
- Report templates

---

## 9. Real-Time Monitoring & Alerting

### Problem
Need real-time visibility into security posture changes.

### Required Components

#### 9.1 Real-Time Finding Ingestion
- Webhook receivers for scanners
- Streaming data processing
- Real-time normalization
- Real-time risk scoring

#### 9.2 Alerting Engine
- Configurable alert rules
- Multi-channel alerts (email, Slack, PagerDuty, etc.)
- Alert aggregation
- Alert fatigue prevention

#### 9.3 Anomaly Detection
- Unusual finding patterns
- Risk spike detection
- Compliance drift detection
- Attack pattern detection

---

## 10. Integration Ecosystem

### Problem
ASPM must integrate seamlessly with existing tooling.

### Required Components

#### 10.1 CI/CD Integration
- Pre-commit hooks
- PR security checks
- Build-time security gates
- Deployment security gates

#### 10.2 SIEM Integration
- Splunk integration
- QRadar integration
- Sentinel integration
- Custom SIEM adapters

#### 10.3 Cloud Provider Integration
- AWS Security Hub
- Azure Security Center
- GCP Security Command Center
- Multi-cloud support

#### 10.4 Identity & Access Management
- SSO integration (SAML, OIDC)
- RBAC integration
- Privileged access management
- Identity provider integration

---

## 11. Data Correlation & Deduplication

### Problem
Same vulnerability may be found by multiple scanners. Need intelligent correlation.

### Required Components

#### 11.1 Finding Correlation Engine
- Cross-scanner deduplication
- Related finding grouping
- Root cause analysis
- Impact analysis

#### 11.2 Attack Path Analysis
- Map vulnerabilities to attack paths
- Identify critical paths
- Prioritize based on attack paths
- Visualize attack surfaces

---

## 12. API & Extensibility

### Problem
Need APIs and extensibility for custom integrations and automation.

### Required Components

#### 12.1 REST API
- Complete CRUD APIs
- Webhook APIs
- Query APIs
- Bulk operations

#### 12.2 GraphQL API
- Flexible querying
- Real-time subscriptions
- Efficient data fetching

#### 12.3 Plugin System
- Custom scanner adapters
- Custom risk scoring models
- Custom workflows
- Custom integrations

#### 12.4 SDKs
- JavaScript/TypeScript SDK
- Python SDK
- Go SDK
- CLI tools

---

## 13. Security & Compliance of the Platform

### Problem
The ASPM platform itself must be secure and compliant.

### Required Components

#### 13.1 Security
- Encryption at rest and in transit
- Secrets management
- Audit logging
- Access controls
- Vulnerability management for the platform

#### 13.2 Compliance
- SOC 2 Type II
- ISO 27001
- GDPR compliance
- Data residency options

---

## 14. User Experience Enhancements

### Problem
Complex security data needs intuitive interfaces.

### Required Components

#### 14.1 Advanced UI Features
- Interactive risk heatmaps
- Attack path visualization
- Dependency graph visualization
- Timeline views
- Comparison views

#### 14.2 Workflow Optimization
- Bulk operations
- Keyboard shortcuts
- Saved filters and views
- Customizable dashboards
- Mobile-responsive design

---

## Implementation Priority

### Phase 1: Foundation (Months 1-3)
1. ✅ Unified security data model **COMPLETED**
2. ✅ Core scanner adapters (6 implemented, more planned) **IN PROGRESS**
3. Asset inventory & discovery
4. Basic risk scoring (implemented in normalization engine)
5. Vulnerability management basics

### Phase 2: Intelligence (Months 4-6)
1. Threat intelligence integration
2. Advanced risk scoring
3. Finding correlation & deduplication
4. Compliance framework mapping
5. Advanced analytics

### Phase 3: Automation (Months 7-9)
1. Remediation workflows
2. Ticketing integration
3. Automated remediation
4. CI/CD deep integration
5. Real-time monitoring

### Phase 4: Scale & Polish (Months 10-12)
1. Additional scanner adapters
2. Advanced reporting
3. Predictive analytics
4. Platform security hardening
5. UX enhancements

---

## Success Metrics

- **Coverage**: % of assets scanned
- **Time to Detection**: Average time from vulnerability introduction to detection
- **Time to Remediation**: Average time from detection to remediation
- **False Positive Rate**: % of findings marked as false positives
- **Risk Reduction**: Reduction in overall risk score over time
- **Compliance Score**: % of compliance requirements met
- **User Adoption**: Active users, API usage, integrations

---

## Next Steps

1. ✅ **Architecture Review**: Design unified data model and normalization engine **COMPLETED**
2. ✅ **Scanner Adapter Framework**: Build extensible adapter framework **COMPLETED**
3. **Asset Discovery**: Implement automated asset discovery
4. ✅ **Risk Scoring MVP**: Build initial risk scoring engine **COMPLETED** (in normalization engine)
5. **Integration Planning**: Prioritize scanner integrations based on customer needs
6. **Additional Scanner Adapters**: Implement remaining adapters (Checkmarx, Veracode, Burp Suite, etc.)
7. **Schema Versioning**: Add versioning and migration support for schema evolution
8. **Real-time Ingestion**: Add webhook receivers for real-time finding ingestion

## Recent Completions

### Unified Security Data Model & Normalization (✅ Completed)
- **Core Schema**: `core/unified-finding-schema.ts` - ECS-compatible unified finding schema
- **ECS Adapter**: `services/ecs-adapter.ts` - Bidirectional ECS conversion
- **Normalization Engine**: `services/normalization-engine.ts` - Full normalization pipeline
- **Scanner Adapters**: 
  - `services/scanner-adapters/base-adapter.ts` - Base adapter framework
  - `services/scanner-adapters/sonarqube-adapter.ts` - SonarQube SAST
  - `services/scanner-adapters/snyk-adapter.ts` - Snyk SCA & Container
  - `services/scanner-adapters/owasp-zap-adapter.ts` - OWASP ZAP DAST
  - `services/scanner-adapters/checkov-adapter.ts` - Checkov IaC
  - `services/scanner-adapters/trivy-adapter.ts` - Trivy Container
  - `services/scanner-adapters/aws-security-hub-adapter.ts` - AWS Security Hub CSPM
- **Backend API**: `dashboard-api/src/unified-findings/` - REST API for findings management
- **Frontend UI**: `dashboard-frontend/src/views/UnifiedFindings.vue` - Unified findings dashboard
- **Supporting Components**: Import modal, detail modal with ECS preview

**Key Features:**
- Full ECS (Elastic Common Schema) compatibility for Elasticsearch integration
- Multi-scanner normalization with deduplication
- Risk scoring based on severity, exploitability, and asset criticality
- Compliance framework mapping (SOC2, PCI-DSS, OWASP, etc.)
- ECS export functionality
- Real-time finding import and management

