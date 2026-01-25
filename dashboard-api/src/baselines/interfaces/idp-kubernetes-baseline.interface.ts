import { BaseBaseline } from './base-baseline.interface';

/**
 * IDP/Kubernetes Data Protection Baseline
 */
export interface IDPKubernetesDataProtectionBaseline extends BaseBaseline {
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
        containsPHI?: boolean;
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
