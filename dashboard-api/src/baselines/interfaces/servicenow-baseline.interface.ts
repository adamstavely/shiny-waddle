import { BaseBaseline } from './base-baseline.interface';

/**
 * ServiceNow Data Protection Baseline
 */
export interface ServiceNowDataProtectionBaseline extends BaseBaseline {
  platform: 'servicenow';
  config: {
    // Access Controls & RBAC
    accessControls?: {
      roles?: Array<{
        name: string;
        description?: string;
        includes?: string[]; // Inherited roles
        admin?: boolean;
        active?: boolean;
      }>;
      acls?: Array<{
        name: string;
        table?: string;
        operation?: 'read' | 'write' | 'create' | 'delete';
        script?: string;
        active?: boolean;
      }>;
      userRoles?: Record<string, string[]>; // username -> roles[]
    };
    
    // Data Classification & Sensitive Data Handling
    dataClassification?: {
      tables?: Record<string, {
        classification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
        containsPII?: boolean;
        containsPHI?: boolean;
        piiTypes?: string[]; // SSN, Email, Phone, CreditCard, etc.
        requiresEncryption?: boolean;
      }>;
      fields?: Record<string, {
        classification?: string;
        containsPII?: boolean;
        containsPHI?: boolean;
        encryptionRequired?: boolean;
        maskingRules?: Array<{
          type: 'hash' | 'redact' | 'partial' | 'tokenize';
          pattern?: string;
        }>;
      }>;
    };
    
    // Encryption & Security
    encryption?: {
      fieldEncryption?: {
        enabled: boolean;
        algorithm?: string;
        keyManagement?: 'ServiceNow Managed' | 'Customer Managed';
        encryptedFields?: string[];
      };
      databaseEncryption?: {
        enabled: boolean;
        tdeEnabled?: boolean; // Transparent Data Encryption
      };
      sslTls?: {
        enabled: boolean;
        tlsVersion?: string;
        certificateManagement?: string;
      };
    };
    
    // Data Retention & Lifecycle
    dataRetention?: {
      policies?: Array<{
        table: string;
        retentionPeriod?: number; // days
        archiveBeforeDelete?: boolean;
        autoDelete?: boolean;
        hipaaCompliant?: boolean; // 6 years minimum
      }>;
      dataArchiving?: {
        enabled: boolean;
        archiveTables?: string[];
      };
    };
    
    // Audit & Compliance
    auditLogging?: {
      tableAuditEnabled?: boolean;
      fieldAuditEnabled?: boolean;
      auditTables?: string[];
      auditFields?: string[];
      hipaaCompliance?: {
        enabled: boolean;
        securityRuleControls?: boolean;
        privacyRuleControls?: boolean;
        breachNotificationRule?: boolean;
        auditRetention?: number; // days, minimum 6 years for HIPAA
      };
    };
    
    // External Data Sharing & Integration
    externalDataSharing?: {
      inboundIntegrations?: Array<{
        name: string;
        type: string; // REST, SOAP, etc.
        authentication?: string;
        ipWhitelist?: string[];
        requireEncryption?: boolean;
      }>;
      outboundIntegrations?: Array<{
        name: string;
        type: string;
        destination?: string;
        encryptionRequired?: boolean;
        dataClassification?: string[];
      }>;
      dataExport?: {
        allowed?: boolean;
        requireApproval?: boolean;
        encryptionRequired?: boolean;
        hipaaDataRequiresApproval?: boolean;
      };
    };
    
    // Multi-Tenancy & Data Isolation
    multiTenancy?: {
      enabled: boolean;
      tenantIsolation?: {
        enabled: boolean;
        isolationLevel?: 'database' | 'schema' | 'row';
      };
      crossTenantAccess?: {
        allowed?: boolean;
        requireExplicitPermission?: boolean;
      };
    };
    
    // API Security
    apiSecurity?: {
      restApi?: {
        authenticationRequired?: boolean;
        oauthEnabled?: boolean;
        ipWhitelist?: string[];
        rateLimiting?: {
          enabled: boolean;
          limit?: number;
        };
      };
      soapApi?: {
        authenticationRequired?: boolean;
        ipWhitelist?: string[];
      };
    };
    
    // Data Masking & Anonymization
    dataMasking?: {
      enabled: boolean;
      maskingRules?: Array<{
        table: string;
        field: string;
        type: 'hash' | 'redact' | 'partial' | 'tokenize';
        pattern?: string;
      }>;
      testDataAnonymization?: {
        enabled: boolean;
        anonymizePHI?: boolean;
      };
    };
  };
}
