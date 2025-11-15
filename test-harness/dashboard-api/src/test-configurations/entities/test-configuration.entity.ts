import { DatabaseConfig, TestQuery, FirewallRule, NetworkSegment, DLPPattern, User, ServiceMeshConfig } from '../../../../core/types';

export type TestConfigurationType = 'rls-cls' | 'network-policy' | 'dlp' | 'api-gateway' | 'distributed-systems' | 'api-security' | 'data-pipeline';

export interface BaseTestConfigurationEntity {
  id: string;
  name: string;
  type: TestConfigurationType;
  description?: string;
  createdAt: Date;
  updatedAt: Date;
  createdBy?: string;
  tags?: string[];
  enabled: boolean;
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

export interface RegionConfig {
  id: string;
  name: string;
  endpoint: string;
  pdpEndpoint?: string;
  timezone?: string;
  latency?: number;
  credentials?: Record<string, string>;
}

export interface DistributedSystemsConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'distributed-systems';
  regions: RegionConfig[];
  policySync?: {
    enabled: boolean;
    syncInterval?: number;
    consistencyLevel?: 'strong' | 'eventual' | 'weak';
  };
  coordination?: {
    type: 'consul' | 'etcd' | 'zookeeper' | 'custom';
    endpoint?: string;
  };
  testLogic?: {
    validateConsistency?: boolean;
    checkSynchronization?: boolean;
    customValidations?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
}

export interface APISecurityConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'api-security';
  baseUrl: string;
  authentication?: {
    type: 'bearer' | 'basic' | 'oauth2' | 'api-key' | 'jwt';
    credentials: Record<string, string>;
  };
  rateLimitConfig?: {
    maxRequests?: number;
    windowSeconds?: number;
    strategy?: 'fixed' | 'sliding' | 'token-bucket';
  };
  headers?: Record<string, string>;
  timeout?: number;
  endpoints?: Array<{
    id: string;
    name: string;
    endpoint: string;
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS';
    apiType: 'rest' | 'graphql' | 'authentication' | 'authorization' | 'rate-limiting' | 'vulnerability';
    expectedStatus?: number;
    expectedAuthRequired?: boolean;
    expectedRateLimit?: boolean;
    body?: any;
    headers?: Record<string, string>;
  }>;
  testLogic?: {
    validateAuthentication?: boolean;
    validateAuthorization?: boolean;
    checkRateLimiting?: boolean;
    selectedTestSuites?: string[];
    customValidations?: Array<{
      name: string;
      condition: string;
      description?: string;
    }>;
  };
}

export interface DataPipelineConfigurationEntity extends BaseTestConfigurationEntity {
  type: 'data-pipeline';
  pipelineType: 'etl' | 'streaming' | 'batch' | 'real-time';
  connection?: {
    type: 'kafka' | 'spark' | 'airflow' | 'dbt' | 'custom';
    endpoint?: string;
    credentials?: Record<string, string>;
  };
  dataSource?: {
    type: 'database' | 'api' | 'file' | 'stream';
    connectionString?: string;
  };
  dataDestination?: {
    type: 'database' | 'data-warehouse' | 'data-lake' | 'api';
    connectionString?: string;
  };
  testLogic?: {
    validateAccessControl?: boolean;
    checkDataQuality?: boolean;
    validateTransformations?: boolean;
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
  | APIGatewayConfigurationEntity
  | DistributedSystemsConfigurationEntity
  | APISecurityConfigurationEntity
  | DataPipelineConfigurationEntity;

