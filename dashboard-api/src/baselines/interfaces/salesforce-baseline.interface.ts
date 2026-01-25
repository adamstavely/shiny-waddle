import { BaseBaseline } from './base-baseline.interface';

/**
 * Salesforce Data Protection Baseline
 */
export interface SalesforceDataProtectionBaseline extends BaseBaseline {
  platform: 'salesforce';
  config: {
    // Data Classification & Labeling
    dataClassification?: {
      fields?: Record<string, {
        classification: 'Public' | 'Internal' | 'Confidential' | 'Restricted';
        containsPII?: boolean;
        containsPHI?: boolean;
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
        containsPHI?: boolean;
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
        criteria?: string;
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
        objects?: string[];
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
      fieldHistoryTracking?: string[];
      loginAuditEnabled?: boolean;
      dataAccessAuditEnabled?: boolean;
      hipaaCompliance?: {
        enabled: boolean;
        securityRuleControls?: boolean;
        privacyRuleControls?: boolean;
        breachNotificationRule?: boolean;
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
