import { DatabaseConfig, TestQuery, FirewallRule, NetworkSegment, DLPPattern, User, ServiceMeshConfig } from '../../../../core/types';

export type TestConfigurationType = 'rls-cls' | 'network-policy' | 'dlp' | 'identity-lifecycle' | 'api-gateway';

export interface BaseTestConfigurationEntity {
  id: string;
  name: string;
  type: TestConfigurationType;
  description?: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  tags?: string[];
}

export interface RLSCLSConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'rls-cls';
  database: DatabaseConfig;
  testQueries: TestQuery[];
  maskingRules?: Array<{
    table: string;
    column: string;
    maskingType: 'partial' | 'full' | 'hash' | 'redact';
    condition?: string;
  }>;
  testResources?: Array<{
    resourceId: string;
    resourceType: string;
    description?: string;
  }>;
  validationRules?: {
    minRLSCoverage?: number;
    minCLSCoverage?: number;
    requiredPolicies?: string[];
  };
  testLogic?: {
    skipDisabledPolicies?: boolean;
    validateCrossTenant?: boolean;
    customValidations?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
}

export interface NetworkPolicyConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'network-policy';
  firewallRules: FirewallRule[];
  networkSegments: NetworkSegment[];
  serviceMeshConfig?: ServiceMeshConfig;
  testLogic?: {
    validateConnectivity?: boolean;
    checkSegmentation?: boolean;
    customRules?: Array<{
      source: string;
      target: string;
      expected: boolean;
      description?: string;
    }>;
  };
}

export interface DLPConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'dlp';
  patterns?: DLPPattern[];
  bulkExportLimits?: {
    csv?: number;
    json?: number;
    excel?: number;
    api?: number;
  };
  piiDetectionRules?: Array<{
    fieldName: string;
    pattern: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  testLogic?: {
    validateAPIResponses?: boolean;
    checkBulkExports?: boolean;
    customChecks?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
}

export interface IdentityLifecycleConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'identity-lifecycle';
  onboardingWorkflow?: {
    steps: Array<{
      name: string;
      required: boolean;
      description?: string;
    }>;
  };
  pamConfig?: {
    maxJITDuration?: number;
    requireApproval?: boolean;
    emergencyAccessEnabled?: boolean;
  };
  credentialRotationRules?: {
    passwordMaxAge?: number;
    apiKeyMaxAge?: number;
    requireMFA?: boolean;
  };
  testLogic?: {
    validateWorkflow?: boolean;
    checkMFA?: boolean;
    customValidations?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
}

export interface APIGatewayConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'api-gateway';
  rateLimitConfig?: {
    defaultLimit?: number;
    defaultTimeWindow?: number;
    perEndpointLimits?: Record<string, { limit: number; window: number }>;
  };
  serviceAuthConfig?: {
    methods: Array<'mtls' | 'jwt' | 'api-key' | 'oauth2'>;
    requiredForEndpoints?: string[];
  };
  gatewayPolicies?: Array<{
    id: string;
    name: string;
    endpoint: string;
    method: string;
    rules: any[];
  }>;
  testLogic?: {
    validateRateLimiting?: boolean;
    checkServiceAuth?: boolean;
    customValidations?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
}

export type TestConfigurationEntity =
  | RLSCLSConfigurationEntity
  | NetworkPolicyConfigurationEntity
  | DLPConfigurationEntity
  | IdentityLifecycleConfigurationEntity
  | APIGatewayConfigurationEntity;

