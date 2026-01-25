# Platform-Specific Data Protection Baselines Implementation Plan

## Overview

This document outlines the plan for implementing platform-specific **data protection baseline** management functionality for Salesforce, Elastic, and IDP/Kubernetes platforms. These baselines focus specifically on **data protection configurations** that safeguard sensitive data (including PHI, PII, and other sensitive information), ensure proper access controls, enforce encryption, and maintain compliance with **HIPAA** and other applicable regulations.

## Goals

1. **Create, manage, and version data protection baselines** for each platform
2. **Compare current data protection configurations against baselines**
3. **Detect drift in data protection settings** (encryption, access controls, retention policies)
4. **Validate data protection configurations** against baselines in tests
5. **Ensure HIPAA compliance** for Protected Health Information (PHI) and other sensitive data
6. **Protect sensitive data** (PHI, PII, financial data, etc.) through proper configuration

## Compliance Requirements

### HIPAA Compliance (Primary Focus)
When handling Protected Health Information (PHI), baselines must validate HIPAA requirements:

#### HIPAA Security Rule (45 CFR §164.308-312)
- **Access Controls** (§164.312(a)(1)): Unique user identification, emergency access procedures
- **Audit Controls** (§164.312(b)): Hardware, software, and procedural mechanisms to record and examine activity
- **Integrity** (§164.312(c)(1)): Controls to ensure PHI is not improperly altered or destroyed
- **Transmission Security** (§164.312(e)(1)): Technical security measures to guard against unauthorized access during transmission
- **Encryption** (§164.312(a)(2)(iv) & §164.312(e)(2)(ii)): Encryption of PHI at rest and in transit

#### HIPAA Privacy Rule (45 CFR §164.502-514)
- **Minimum Necessary** (§164.502(b)): Limit PHI access to minimum necessary to accomplish intended purpose
- **Uses and Disclosures** (§164.502): Restrictions on PHI use and disclosure
- **Right to Access** (§164.524): Patients' right to access their PHI
- **Right to Amendment** (§164.526): Patients' right to request PHI amendments

#### HIPAA Breach Notification Rule (45 CFR §164.400-414)
- **Breach Detection**: Mechanisms to detect unauthorized PHI access
- **Breach Notification**: Procedures for notifying affected individuals and HHS

### Other Compliance Considerations
While HIPAA is the primary compliance framework, baselines should also support general data protection best practices that may be required by other regulations or organizational policies.

## Data Protection Focus Areas

### Core Data Protection Principles
- **Encryption**: Data at rest and in transit
- **Access Controls**: Who can access what data
- **Data Classification**: Labeling and handling of sensitive data
- **Data Retention**: How long data is kept
- **Data Sharing**: Rules for sharing sensitive data
- **Audit Logging**: Tracking data access and changes
- **Secrets Management**: Secure handling of credentials and keys

### Platform-Specific Data Protection Priorities

#### Salesforce
- **Field-Level Security (FLS)**: Ensure proper field access controls for sensitive data (including PHI)
- **Data Sharing Rules**: Prevent unauthorized data sharing (HIPAA minimum necessary for PHI)
- **PHI/PII Detection**: Identify and classify sensitive fields (PHI: patient names, SSN, medical records; PII: email, phone, etc.)
- **Encryption**: Field encryption, platform encryption, Shield encryption (HIPAA Security Rule requirement for PHI)
- **Data Retention**: Retention policies (HIPAA: 6 years minimum for PHI), data deletion policies
- **External Sharing**: Connected apps, data export controls (HIPAA Business Associate Agreements for PHI)
- **Audit Logging**: Track all sensitive data access (HIPAA audit requirement for PHI)

#### Elastic
- **Encryption**: Transport TLS, HTTP TLS, encryption at rest (HIPAA Security Rule requirement for PHI)
- **Access Controls**: Document-level security, field-level security, role-based access (HIPAA access controls for PHI)
- **Data Classification**: Index and field classification, PHI/PII detection
- **Data Retention**: ILM policies, retention periods (HIPAA: 6 years minimum for PHI)
- **Multi-Tenancy**: Data isolation, cross-tenant access controls (prevent unauthorized access to sensitive data)
- **Data Anonymization**: Data masking in ingest pipelines (de-identification for HIPAA PHI)
- **Audit Logging**: Comprehensive audit logs for sensitive data access (HIPAA audit requirement for PHI)

#### IDP/Kubernetes
- **Secrets Management**: Encrypted secrets, key rotation, RBAC for secrets (protect sensitive data credentials)
- **RBAC for Data**: Role-based access to data resources (PVCs, ConfigMaps, Secrets) - minimum necessary access (HIPAA requirement for PHI)
- **Network Policies**: Data isolation between namespaces and pods (prevent unauthorized access to sensitive data)
- **Pod Security**: Restricted mode for data-handling containers (secure processing of sensitive data)
- **Data Classification**: Namespace and pod labels for data types (PHI, PII, etc.)
- **Encryption at Rest**: Volume encryption, key management (HIPAA Security Rule requirement for PHI)
- **Audit Logging**: Data access tracking, compliance logging (HIPAA requirement: all PHI access must be logged)

---

## Architecture

### Shared Components

All platform baselines will share a common base structure:

```typescript
interface BaseBaseline {
  id: string;
  name: string;
  description: string;
  environment: string; // production, staging, development
  version: string;
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes';
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  tags?: string[];
  isActive: boolean;
}
```

### Platform-Specific Structures

Each platform will have its own typed configuration structure:

#### Salesforce Data Protection Baseline
```typescript
interface SalesforceDataProtectionBaseline extends BaseBaseline {
  platform: 'salesforce';
  config: {
    // Data Classification & Labeling
    dataClassification?: {
      fields?: Record<string, {
        classification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
        containsPII?: boolean;
        piiTypes?: string[]; // SSN, Email, Phone, CreditCard, etc.
        encryptionRequired?: boolean;
        retentionPolicy?: {
          duration?: number; // days
          autoDelete?: boolean;
        };
      }>;
      objects?: Record<string, {
        defaultClassification?: string;
        requiresEncryption?: boolean;
      }>;
    };
    
    // Field-Level Security (FLS)
    fieldLevelSecurity?: {
      profiles?: Record<string, {
        fields?: Record<string, {
          readable: boolean;
          editable: boolean;
        }>;
      }>;
      permissionSets?: Record<string, {
        fields?: Record<string, {
          readable: boolean;
          editable: boolean;
        }>;
      }>;
    };
    
    // Data Sharing & Access Controls
    sharingModel?: {
      defaultAccess?: 'Private' | 'Public Read Only' | 'Public Read/Write';
      sharingRules?: Array<{
        name: string;
        objectType: string;
        accessLevel: 'Read' | 'Read/Write';
        criteria?: string; // Sharing rule criteria
        publicGroups?: string[];
        roles?: string[];
      }>;
      orgWideDefaults?: Record<string, 'Private' | 'Public Read Only' | 'Public Read/Write'>;
    };
    
    // Encryption & Security
    encryption?: {
      fieldEncryption?: {
        enabled: boolean;
        algorithm?: string;
        keyManagement?: 'Salesforce Managed' | 'Customer Managed';
      };
      platformEncryption?: {
        enabled: boolean;
        objects?: string[]; // Objects with platform encryption
      };
      shieldPlatformEncryption?: {
        enabled: boolean;
        encryptedFields?: string[];
      };
    };
    
    // Data Retention & Deletion
    dataRetention?: {
      policies?: Array<{
        objectType: string;
        retentionPeriod?: number; // days
        archiveBeforeDelete?: boolean;
        autoDelete?: boolean;
      }>;
      dataResidency?: {
        enabled: boolean;
        region?: string;
      };
    };
    
    // Audit & Compliance
    auditLogging?: {
      fieldHistoryTracking?: string[]; // Objects with field history
      loginAuditEnabled?: boolean;
      dataAccessAuditEnabled?: boolean;
      hipaaCompliance?: {
        enabled: boolean;
        securityRuleControls?: boolean; // Encryption, access controls, audit logging
        privacyRuleControls?: boolean; // Minimum necessary access, data sharing
        breachNotificationRule?: boolean; // Breach detection and notification
      };
    };
    
    // External Data Sharing
    externalDataSharing?: {
      connectedApps?: Array<{
        name: string;
        oauthScopes?: string[];
        ipRanges?: string[];
        requireMFA?: boolean;
      }>;
      dataExport?: {
        allowed?: boolean;
        requireApproval?: boolean;
        encryptionRequired?: boolean;
      };
    };
  };
}
```

#### Elastic Data Protection Baseline
```typescript
interface ElasticDataProtectionBaseline extends BaseBaseline {
  platform: 'elastic';
  config: {
    // Encryption
    encryption?: {
      transport?: {
        enabled: boolean;
        tlsVersion?: string;
        certificateAuthorities?: string[];
      };
      http?: {
        enabled: boolean;
        tlsVersion?: string;
        certificateAuthorities?: string[];
      };
      atRest?: {
        enabled: boolean;
        algorithm?: string;
        keyManagement?: 'Elastic Managed' | 'Customer Managed';
      };
    };
    
    // Access Controls & RBAC
    accessControls?: {
      roles?: Array<{
        name: string;
        clusterPrivileges?: string[];
        indexPrivileges?: Array<{
          names: string[]; // index patterns
          privileges: string[];
          fieldLevelSecurity?: Record<string, string[]>; // field: [allowed_values]
          query?: string; // document-level security query
        }>;
        applicationPrivileges?: Array<{
          application: string;
          privileges: string[];
          resources: string[];
        }>;
      }>;
      users?: Array<{
        username: string;
        roles: string[];
        enabled: boolean;
        metadata?: Record<string, any>;
      }>;
      apiKeys?: {
        requireScoping?: boolean;
        maxAge?: number; // days
        requireMetadata?: boolean;
      };
    };
    
    // Data Classification & Sensitive Data Handling
    dataClassification?: {
      indices?: Array<{
        pattern: string;
        classification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
        containsPII?: boolean;
        piiTypes?: string[];
        requiresEncryption?: boolean;
      }>;
      fieldMappings?: Record<string, {
        classification?: string;
        containsPII?: boolean;
        maskingRules?: Array<{
          type: 'hash' | 'redact' | 'partial' | 'tokenize';
          pattern?: string;
        }>;
      }>;
    };
    
    // Data Retention & Lifecycle Management
    dataRetention?: {
      ilmPolicies?: Array<{
        name: string;
        phases: {
          hot?: {
            minAge?: string;
            actions?: Record<string, any>;
          };
          warm?: {
            minAge?: string;
            actions?: Record<string, any>;
          };
          cold?: {
            minAge?: string;
            actions?: Record<string, any>;
          };
          delete?: {
            minAge: string; // retention period
            actions?: {
              delete?: boolean;
            };
          };
        };
      }>;
      indexTemplates?: Array<{
        name: string;
        indexPatterns: string[];
        template?: {
          settings?: Record<string, any>;
          mappings?: Record<string, any>;
          aliases?: Record<string, any>;
        };
        priority?: number;
        ilmPolicy?: string;
      }>;
    };
    
    // Multi-Tenancy & Data Isolation
    multiTenancy?: {
      enabled: boolean;
      isolationLevel?: 'index' | 'document' | 'field';
      tenantFields?: string[];
      crossTenantAccess?: {
        allowed?: boolean;
        requireExplicitPermission?: boolean;
      };
    };
    
    // Audit Logging
    auditLogging?: {
      enabled: boolean;
      events?: string[]; // 'access_granted', 'access_denied', 'anonymous_access_denied', etc.
      includeRequestBody?: boolean;
      hipaaCompliance?: {
        enabled: boolean;
        securityRuleControls?: boolean; // Encryption, access controls, audit logging
        privacyRuleControls?: boolean; // Minimum necessary access, data sharing
        breachNotificationRule?: boolean; // Breach detection and notification
      };
    };
    
    // Snapshots & Backup
    snapshots?: {
      repositories?: Array<{
        name: string;
        type: string;
        settings?: Record<string, any>;
        encryptionEnabled?: boolean;
      }>;
      policies?: Array<{
        name: string;
        schedule: string;
        indices: string[];
        retention?: {
          expireAfter?: string;
          maxCount?: number;
        };
      }>;
    };
    
    // Anonymization & Masking
    dataAnonymization?: {
      ingestPipelines?: Array<{
        name: string;
        processors?: Array<{
          type: 'set' | 'script' | 'fingerprint';
          field: string;
          value?: string;
          script?: string;
          method?: 'sha256' | 'sha1' | 'md5';
        }>;
      }>;
    };
  };
}
```

#### IDP/Kubernetes Data Protection Baseline
```typescript
interface IDPKubernetesDataProtectionBaseline extends BaseBaseline {
  platform: 'idp-kubernetes';
  config: {
    // Secrets Management
    secretsManagement?: {
      secretStores?: Array<{
        name: string;
        type: 'kubernetes' | 'vault' | 'aws-secrets-manager' | 'azure-key-vault';
        encryption?: {
          enabled: boolean;
          algorithm?: string;
          keyRotation?: {
            enabled: boolean;
            interval?: number; // days
          };
        };
      }>;
      secretAccess?: {
        rbacRequired?: boolean;
        auditLogging?: boolean;
        rotationPolicy?: {
          maxAge?: number; // days
          requireRotation?: boolean;
        };
      };
    };
    
    // RBAC for Data Access
    rbacDataAccess?: {
      roles?: Array<{
        name: string;
        namespace?: string;
        rules?: Array<{
          apiGroups: string[];
          resources: string[];
          verbs: string[];
          resourceNames?: string[];
        }>;
      }>;
      roleBindings?: Array<{
        name: string;
        namespace?: string;
        roleRef: {
          kind: string;
          name: string;
        };
        subjects: Array<{
          kind: string;
          name: string;
          namespace?: string;
        }>;
      }>;
      clusterRoles?: Array<{
        name: string;
        rules: Array<{
          apiGroups: string[];
          resources: string[];
          verbs: string[];
        }>;
      }>;
    };
    
    // Network Policies for Data Isolation
    networkPolicies?: Array<{
      name: string;
      namespace: string;
      podSelector?: Record<string, string>;
      policyTypes: ('Ingress' | 'Egress')[];
      ingress?: Array<{
        from?: Array<{
          podSelector?: Record<string, string>;
          namespaceSelector?: Record<string, string>;
          ipBlock?: {
            cidr: string;
            except?: string[];
          };
        }>;
        ports?: Array<{
          protocol: string;
          port?: number;
        }>;
      }>;
      egress?: Array<{
        to?: Array<{
          podSelector?: Record<string, string>;
          namespaceSelector?: Record<string, string>;
          ipBlock?: {
            cidr: string;
          };
        }>;
        ports?: Array<{
          protocol: string;
          port?: number;
        }>;
      }>;
    }>;
    
    // Pod Security Standards for Data Containers
    podSecurityStandards?: {
      enforce?: 'restricted' | 'baseline' | 'privileged';
      audit?: 'restricted' | 'baseline' | 'privileged';
      warn?: 'restricted' | 'baseline' | 'privileged';
      namespaceOverrides?: Record<string, {
        enforce?: string;
        audit?: string;
        warn?: string;
      }>;
    };
    
    // Data Classification Labels
    dataClassification?: {
      namespaces?: Record<string, {
        classification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
        containsPII?: boolean;
        requiresEncryption?: boolean;
      }>;
      podLabels?: Record<string, {
        classification?: string;
        dataTypes?: string[]; // PHI, PII (HIPAA identifiers)
      }>;
    };
    
    // Encryption at Rest
    encryptionAtRest?: {
      enabled: boolean;
      provider?: 'kubernetes' | 'cloud-provider';
      keyManagement?: {
        type: string;
        rotationEnabled?: boolean;
      };
    };
    
    // Data Retention & Lifecycle
    dataRetention?: {
      pvcRetention?: {
        defaultRetention?: number; // days
        perNamespace?: Record<string, number>;
      };
      jobCleanup?: {
        ttlAfterFinished?: number; // seconds
      };
      podCleanup?: {
        maxAge?: number; // days
      };
    };
    
    // Audit Logging
    auditLogging?: {
      enabled: boolean;
      logLevel?: 'None' | 'Metadata' | 'Request' | 'RequestResponse';
      auditPolicy?: {
        rules?: Array<{
          level: string;
          namespaces?: string[];
          verbs?: string[];
          resources?: string[];
        }>;
      };
    };
    
    // Golden Path Templates (Data Protection Focus)
    goldenPathTemplates?: Array<{
      name: string;
      description: string;
      template: {
        metadata?: {
          labels?: Record<string, string>;
          annotations?: Record<string, string>;
        };
        spec?: {
          securityContext?: {
            runAsNonRoot?: boolean;
            runAsUser?: number;
            fsGroup?: number;
            seccompProfile?: {
              type: string;
            };
          };
          containers?: Array<{
            name: string;
            securityContext?: {
              allowPrivilegeEscalation?: boolean;
              readOnlyRootFilesystem?: boolean;
              capabilities?: {
                drop?: string[];
                add?: string[];
              };
            };
            volumeMounts?: Array<{
              name: string;
              mountPath: string;
              readOnly?: boolean;
            }>;
          }>;
          volumes?: Array<{
            name: string;
            secret?: {
              secretName: string;
            };
            configMap?: {
              name: string;
            };
          }>;
        };
      };
    }>;
    
    // Approved Registries & Sidecars (Security Focus)
    approvedRegistries?: string[];
    allowedSidecars?: Array<{
      name: string;
      image: string;
      securityContext?: Record<string, any>;
    }>;
  };
}
```

---

## Implementation Phases

### Phase 1: Foundation (Week 1-2)

#### 1.1 Backend Infrastructure
- [ ] Create base baseline service interface
- [ ] Create platform-specific modules:
  - `salesforce-baselines/`
  - `elastic-baselines/`
  - `idp-kubernetes-baselines/`
- [ ] Implement shared baseline repository pattern
- [ ] Create data models and DTOs for each platform
- [ ] Set up data storage (JSON files initially, DB migration ready)

#### 1.2 Core API Endpoints
Each platform will have:
```
GET    /api/v1/{platform}/baselines              - List all baselines
POST   /api/v1/{platform}/baselines              - Create baseline
GET    /api/v1/{platform}/baselines/:id          - Get baseline
PUT    /api/v1/{platform}/baselines/:id          - Update baseline
DELETE /api/v1/{platform}/baselines/:id          - Delete baseline
POST   /api/v1/{platform}/baselines/:id/compare  - Compare with current config
POST   /api/v1/{platform}/baselines/:id/detect-drift - Detect drift
GET    /api/v1/{platform}/baselines/:id/versions - Get version history
```

#### 1.3 Frontend Base Components
- [ ] Create shared `BaselineCard.vue` component
- [ ] Create shared `BaselineForm.vue` component
- [ ] Create shared `BaselineComparison.vue` component
- [ ] Create shared `DriftDetection.vue` component

---

### Phase 2: Salesforce Data Protection Baselines (Week 3-4)

#### 2.1 Backend Implementation
- [ ] Implement `SalesforceDataProtectionBaselineService`
- [ ] Create Salesforce data protection DTOs and validators
- [ ] Implement data classification detection and validation
- [ ] Implement field-level security comparison
- [ ] Implement sharing model drift detection
- [ ] Implement encryption configuration validation
- [ ] Implement data retention policy checks

#### 2.2 Frontend Implementation
- [ ] Build Salesforce data protection baseline list view
- [ ] Build Salesforce baseline creation form with **data protection sections**:
  - **Data Classification**: Field and object classification, PHI/PII detection
  - **Field-Level Security**: Profile and permission set FLS configuration
  - **Data Sharing Model**: Sharing rules, org-wide defaults, public group access
  - **Encryption Settings**: Field encryption, platform encryption, Shield encryption
  - **Data Retention**: Retention policies, data residency, auto-deletion
  - **Audit & Compliance**: Field history tracking, compliance frameworks
  - **External Data Sharing**: Connected apps, data export controls
- [ ] Build comparison view highlighting **data protection differences**
- [ ] Build drift detection results view with **data protection risk scoring**
- [ ] Add PHI/PII detection and classification helpers (HIPAA identifiers)
- [ ] Add Salesforce API integration for fetching current data protection config

#### 2.3 Features
- [ ] Import data protection baseline from Salesforce org
- [ ] Export baseline to JSON/YAML
- [ ] **PHI/PII field detection and classification** (patient names, SSN, medical records, etc.)
- [ ] **HIPAA compliance scoring** for healthcare data
- [ ] **Encryption gap analysis**
- [ ] **Sharing rule risk assessment**
- [ ] Version management
- [ ] Baseline activation/deactivation
- [ ] Tag-based organization

---

### Phase 3: Elastic Data Protection Baselines (Week 5-6)

#### 3.1 Backend Implementation
- [ ] Implement `ElasticDataProtectionBaselineService`
- [ ] Create Elastic data protection DTOs and validators
- [ ] Implement encryption configuration validation (transport, HTTP, at-rest)
- [ ] Implement RBAC and access control comparison
- [ ] Implement data classification and sensitive data detection
- [ ] Implement ILM policy validation for data retention
- [ ] Implement multi-tenancy isolation checks
- [ ] Implement audit logging configuration validation

#### 3.2 Frontend Implementation
- [ ] Build Elastic data protection baseline list view
- [ ] Build Elastic baseline creation form with **data protection sections**:
  - **Encryption**: Transport TLS, HTTP TLS, encryption at rest
  - **Access Controls**: Roles, users, API keys, document-level security, field-level security
  - **Data Classification**: Index classification, PHI/PII detection, field mappings
  - **Data Retention**: ILM policies, index templates, retention periods
  - **Multi-Tenancy**: Data isolation, cross-tenant access controls
  - **Audit Logging**: Event logging, compliance frameworks
  - **Snapshots & Backup**: Repository encryption, backup policies
  - **Data Anonymization**: Ingest pipelines for PII masking
- [ ] Build comparison view highlighting **encryption and access control differences**
- [ ] Build drift detection results view with **data protection risk scoring**
- [ ] Add PII detection in index mappings
- [ ] Add Elastic API integration for fetching current data protection config

#### 3.3 Features
- [ ] Import data protection baseline from Elastic cluster
- [ ] Export baseline to JSON/YAML
- [ ] **Encryption gap detection** (missing TLS, unencrypted indices)
- [ ] **Access control risk analysis** (overprivileged roles, missing DLS/FLS)
- [ ] **HIPAA retention compliance** (retention requirements, data deletion policies)
- [ ] **Multi-tenancy isolation validation**
- [ ] **PHI/PII field detection** in index mappings (HIPAA identifiers)
- [ ] Version management
- [ ] Baseline activation/deactivation
- [ ] Multi-cluster support

---

### Phase 4: IDP/Kubernetes Data Protection Baselines (Week 7-8)

#### 4.1 Backend Implementation
- [ ] Implement `IDPKubernetesDataProtectionBaselineService`
- [ ] Create IDP/K8s data protection DTOs and validators
- [ ] Implement secrets management validation
- [ ] Implement RBAC data access validation
- [ ] Implement network policy isolation checks
- [ ] Implement pod security standards validation
- [ ] Implement encryption at rest validation
- [ ] Implement audit logging configuration

#### 4.2 Frontend Implementation
- [ ] Build IDP/K8s data protection baseline list view
- [ ] Build IDP/K8s baseline creation form with **data protection sections**:
  - **Secrets Management**: Secret stores, encryption, key rotation
  - **RBAC for Data Access**: Roles, role bindings, cluster roles for data resources
  - **Network Policies**: Data isolation, ingress/egress controls, namespace isolation
  - **Pod Security Standards**: Restricted mode for data containers
  - **Data Classification**: Namespace and pod labels for data classification
  - **Encryption at Rest**: Provider configuration, key management
  - **Data Retention**: PVC retention, job/pod cleanup policies
  - **Audit Logging**: Audit policy, compliance logging
  - **Golden Path Templates**: Secure templates for data-handling workloads
- [ ] Build comparison view highlighting **secrets and access control differences**
- [ ] Build drift detection results view with **data protection risk scoring**
- [ ] Add Kubernetes API integration for fetching current data protection config

#### 4.3 Features
- [ ] Import data protection baseline from Kubernetes cluster
- [ ] Export baseline to YAML
- [ ] **Secrets exposure detection** (unencrypted secrets, missing RBAC)
- [ ] **Network isolation validation** (missing network policies, cross-namespace access)
- [ ] **RBAC risk analysis** (overprivileged roles, missing data access controls)
- [ ] **Pod security compliance** (privileged containers, root access)
- [ ] **Data classification enforcement** (namespace labels, pod labels)
- [ ] Version management
- [ ] Baseline activation/deactivation
- [ ] Multi-cluster support
- [ ] Namespace-scoped baselines

---

### Phase 5: Advanced Data Protection Features (Week 9-10)

#### 5.1 Data Protection Comparison & Drift Detection
- [ ] Visual diff viewer for **data protection configuration changes**
- [ ] **Data protection risk scoring** (encryption gaps, access control issues, compliance violations)
- [ ] **Automated data protection alerts** (PHI exposure, encryption failures, access violations)
- [ ] **Data protection remediation suggestions** (specific fixes for encryption, access controls)
- [ ] Historical data protection drift tracking
- [ ] **HIPAA compliance gap analysis** (identify missing HIPAA controls)

#### 5.2 Integration with Data Protection Tests
- [ ] Link baselines to **data protection test suites**
- [ ] Auto-generate **data protection validation tests** from baselines
- [ ] **HIPAA compliance scoring** per baseline
- [ ] Test results linked to baseline versions
- [ ] **PHI detection tests** based on baseline classifications (HIPAA identifiers)
- [ ] **Encryption validation tests** based on baseline encryption configs

#### 5.3 Data Protection Baseline Management
- [ ] **HIPAA-compliant baseline templates** (pre-configured HIPAA controls)
- [ ] Baseline inheritance (environment-specific data protection overrides)
- [ ] Baseline merging with **data protection conflict resolution**
- [ ] **Data protection baseline approval workflow**
- [ ] Baseline audit logging for **data protection changes**

#### 5.4 Data Protection UI Enhancements
- [ ] Baseline search and filtering by **data protection criteria** (encryption, PHI, HIPAA compliance)
- [ ] Baseline comparison matrix showing **data protection differences**
- [ ] **Data protection risk dashboard** (encryption coverage, access control gaps, compliance status)
- [ ] **PHI inventory view** (all PHI fields across baselines, HIPAA identifiers)
- [ ] Baseline export/import with **data protection metadata**
- [ ] Bulk operations for **data protection settings**

---

## Technical Details

### Data Storage

**Initial Implementation:**
- JSON files in `dashboard-api/data/`:
  - `salesforce-baselines.json`
  - `elastic-baselines.json`
  - `idp-kubernetes-baselines.json`

**Future Migration:**
- Database tables with JSON columns for flexibility
- Version history table
- Audit log table

### API Design

**RESTful endpoints with consistent patterns:**
- Use platform prefix: `/api/v1/salesforce/`, `/api/v1/elastic/`, `/api/v1/idp-kubernetes/`
- Consistent response formats
- Proper error handling
- Validation at DTO level

### Frontend Architecture

**Component Structure:**
```
views/policies/
  ├── SalesforceBaselinesPolicies.vue (main page)
  ├── elastic/
  │   ├── ElasticBaselineList.vue
  │   ├── ElasticBaselineForm.vue
  │   ├── ElasticBaselineDetail.vue
  │   └── ElasticBaselineCompare.vue
  ├── salesforce/
  │   ├── SalesforceBaselineList.vue
  │   ├── SalesforceBaselineForm.vue
  │   ├── SalesforceBaselineDetail.vue
  │   └── SalesforceBaselineCompare.vue
  └── idp-kubernetes/
      ├── IDPBaselineList.vue
      ├── IDPBaselineForm.vue
      ├── IDPBaselineDetail.vue
      └── IDPBaselineCompare.vue

components/baselines/
  ├── BaselineCard.vue (shared)
  ├── BaselineFormBase.vue (shared)
  ├── BaselineComparison.vue (shared)
  ├── DriftDetection.vue (shared)
  └── VersionHistory.vue (shared)
```

### Validation & Testing

**Backend:**
- Unit tests for each baseline service
- Integration tests for API endpoints
- Validation tests for DTOs
- Comparison algorithm tests

**Frontend:**
- Component unit tests
- E2E tests for baseline workflows
- Form validation tests

---

## Success Metrics

1. **Data Protection Functionality:**
   - ✅ Users can create, edit, and delete **data protection baselines** for each platform
   - ✅ Users can compare current **data protection configs** against baselines
   - ✅ Users can detect **data protection drift** (encryption, access controls, retention)
   - ✅ Baselines integrate with existing **data protection test suites**
   - ✅ **PHI/PII detection and classification** works across all platforms (HIPAA identifiers)
   - ✅ **Encryption gap detection** identifies missing encryption configurations
   - ✅ **Access control risk analysis** identifies overprivileged access

2. **Compliance:**
   - ✅ **HIPAA compliance scoring** per baseline (primary focus)
   - ✅ **HIPAA compliance validation** for Protected Health Information (PHI)
   - ✅ **HIPAA Security Rule controls** validation (encryption, access controls, audit logging)
   - ✅ **HIPAA Privacy Rule controls** validation (minimum necessary access, data sharing)
   - ✅ **HIPAA Breach Notification Rule** compliance checks
   - ✅ **General data protection** best practices validation

3. **Performance:**
   - Data protection baseline comparison completes in < 2 seconds
   - Drift detection completes in < 5 seconds
   - PHI/PII detection completes in < 3 seconds
   - UI remains responsive with 100+ baselines

4. **Usability:**
   - Data protection baseline creation workflow < 5 minutes
   - Clear visual feedback for **data protection risks**
   - Intuitive comparison views highlighting **encryption and access control differences**
   - **Data protection risk dashboard** provides actionable insights

---

## Unified UX: Platform Configuration Management

### Streamlined User Experience

Instead of having separate concepts for "Baselines" and "Configuration Validation", we unify them into a single **Platform Configuration** concept:

**One Unified Flow:**
1. **Create Platform Configuration** = Baseline + Connection Info + Validation Rules (all in one)
2. **Validate** = Compare live system against configuration (one button)
3. **Monitor** = Track compliance and drift over time

### Unified Platform Configuration Structure

```typescript
interface PlatformConfiguration {
  // Identity
  id: string;
  name: string;
  description: string;
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes';
  environment: 'production' | 'staging' | 'development';
  
  // Connection (optional - for live validation)
  connection?: {
    type: 'api' | 'sdk' | 'manual';
    credentials?: Record<string, any>; // Encrypted
    endpoint?: string;
  };
  
  // Baseline Configuration (desired state)
  baseline: {
    // Platform-specific config structure
    // (Salesforce, Elastic, or IDP/K8s config)
  };
  
  // Validation Rules (derived from baseline + custom rules)
  validationRules?: Array<{
    id: string;
    name: string;
    check: string; // e.g., "encryption.enabled === true"
    severity: 'critical' | 'high' | 'medium' | 'low';
    autoGenerated: boolean; // True if derived from baseline
  }>;
  
  // Metadata
  version: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}
```

### User Workflow

**Before (Confusing):**
- "Create Baseline" → Define desired config
- "Create Validation Target" → Define connection
- "Create Validation Rules" → Define checks
- "Run Validation" → Check if live matches

**After (Unified):**
- "Create Platform Configuration" → Define desired config + connection (optional) + validation rules (auto-generated from baseline)
- "Validate" → One button compares live system to configuration
- "View Results" → See compliance status, drift, and issues

### Benefits

1. **Single Source of Truth:** Configuration = Baseline + Connection + Rules
2. **Auto-Generated Rules:** Validation rules automatically derived from baseline config
3. **Optional Live Validation:** Connection info optional - can use for manual comparison too
4. **Clear Mental Model:** "This is how Salesforce should be configured" → "Is it configured that way?"

### Relationship with Environment Configuration Testing

**Platform Configurations** (this feature):
- Platform-specific data protection configurations
- Can validate against live systems via API
- Environment-specific (prod/staging/dev)

**Environment Configuration Testing** (existing feature):
- Cross-platform infrastructure concerns
- Environment variables, secrets management infrastructure
- Configuration files, environment policies
- **Different layer** - infrastructure vs application/platform

**They remain separate** because they operate at different layers, but Platform Configurations now unifies baselines + validation into one concept.

---

## Dependencies

### External APIs
- **Salesforce:** Salesforce REST API (optional)
- **Elastic:** Elasticsearch REST API
- **Kubernetes:** Kubernetes API

### Internal Dependencies
- Existing test framework
- Policy management system
- Environment config service (for drift detection) - complementary, not redundant

---

## Risk Mitigation

1. **API Rate Limits:**
   - Implement caching for external API calls
   - Add retry logic with exponential backoff
   - Provide manual import option

2. **Large Configurations:**
   - Implement pagination for large configs
   - Use streaming for large comparisons
   - Optimize comparison algorithms

3. **Schema Evolution:**
   - Use versioned schemas
   - Migration utilities for baseline updates
   - Backward compatibility checks

---

## Future Enhancements

1. **Multi-platform baselines** (baselines that span multiple platforms)
2. **Baseline templates marketplace**
3. **AI-powered drift analysis**
4. **Automated baseline generation from production**
5. **HIPAA compliance reporting** (Security Rule, Privacy Rule, Breach Notification Rule)
6. **Baseline change impact analysis** (HIPAA impact assessment)

---

## Timeline Summary

- **Weeks 1-2:** Foundation & Infrastructure
- **Weeks 3-4:** Salesforce Baselines
- **Weeks 5-6:** Elastic Baselines
- **Weeks 7-8:** IDP/Kubernetes Baselines
- **Weeks 9-10:** Advanced Features & Polish

**Total Estimated Time:** 10 weeks

---

## Next Steps

1. Review and approve this plan
2. Set up project tracking (GitHub issues/board)
3. Begin Phase 1 implementation
4. Schedule weekly progress reviews
