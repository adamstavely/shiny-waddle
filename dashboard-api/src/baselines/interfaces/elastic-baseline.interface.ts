import { BaseBaseline } from './base-baseline.interface';

/**
 * Elastic Data Protection Baseline
 */
export interface ElasticDataProtectionBaseline extends BaseBaseline {
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
          names: string[];
          privileges: string[];
          fieldLevelSecurity?: Record<string, string[]>;
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
        containsPHI?: boolean;
        piiTypes?: string[];
        requiresEncryption?: boolean;
      }>;
      fieldMappings?: Record<string, {
        classification?: string;
        containsPII?: boolean;
        containsPHI?: boolean;
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
            minAge: string;
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
      events?: string[];
      includeRequestBody?: boolean;
      hipaaCompliance?: {
        enabled: boolean;
        securityRuleControls?: boolean;
        privacyRuleControls?: boolean;
        breachNotificationRule?: boolean;
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
