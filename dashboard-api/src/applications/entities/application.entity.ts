import { ApplicationType, ApplicationStatus } from '../dto/create-application.dto';
import { DatabaseConfig, TestQuery, FirewallRule, NetworkSegment, DLPPattern, ServiceMeshConfig } from '../../../../heimdall-framework/core/types';

export interface ValidatorOverride {
  enabled: boolean;
  reason?: string;
  updatedBy?: string;
  updatedAt?: Date;
}

// Platform Instance infrastructure (for migrated platform instances)
export interface PlatformInstanceInfrastructure {
  platform: 'salesforce' | 'elastic' | 'idp-kubernetes' | 'servicenow';
  connection: {
    endpoint?: string;
    credentials?: Record<string, any>; // Encrypted
  };
  testSuiteId?: string; // Reference to Test Suite (migrated from baseline)
}

// Application Infrastructure Types
export interface ApplicationInfrastructure {
  // Database infrastructure
  databases?: DatabaseInfrastructure[];
  
  // Network infrastructure
  networkSegments?: NetworkSegmentInfrastructure[];
  
  // DLP infrastructure
  dlp?: DLPInfrastructure;
  
  // API Gateway infrastructure
  apiGateway?: APIGatewayInfrastructure;
  
  // Distributed Systems infrastructure
  distributedSystems?: DistributedSystemsInfrastructure;
  
  // API Security infrastructure
  apiSecurity?: APISecurityInfrastructure;
  
  // Data Pipeline infrastructure
  dataPipeline?: DataPipelineInfrastructure;
  
  // Platform Instance infrastructure (for migrated platform instances)
  platformInstance?: PlatformInstanceInfrastructure;
}

export interface DatabaseInfrastructure {
  id: string;
  name: string;
  type: 'postgresql' | 'mysql' | 'mssql' | 'oracle' | 'sqlite';
  host: string;
  port: number;
  database: string;
  // Note: username/password come from runtime config (security)
  testQueries?: TestQuery[];
  maskingRules?: Array<{
    table: string;
    column: string;
    maskingType: 'partial' | 'full' | 'hash' | 'redact';
    condition?: string;
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

export interface NetworkSegmentInfrastructure {
  id: string;
  name: string;
  cidr?: string;
  firewallRules?: FirewallRule[];
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

export interface DLPInfrastructure {
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
  exportRestrictions?: {
    restrictedFields?: string[];
    requireMasking?: boolean;
    allowedFormats?: string[];
  };
  aggregationRequirements?: {
    minK?: number;
    requireAggregation?: boolean;
  };
  fieldRestrictions?: {
    disallowedFields?: string[];
    allowedFields?: string[];
  };
  joinRestrictions?: {
    disallowedJoins?: string[];
  };
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

export interface APIGatewayInfrastructure {
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

export interface DistributedSystemsInfrastructure {
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

export interface APISecurityInfrastructure {
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

export interface DataPipelineInfrastructure {
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

export interface Application {
  id: string;
  name: string;
  type: ApplicationType;
  status: ApplicationStatus;
  baseUrl?: string;
  team?: string;
  description?: string;
  config?: Record<string, any>;
  
  // Infrastructure config
  infrastructure?: ApplicationInfrastructure;
  
  validatorOverrides?: {
    [validatorId: string]: ValidatorOverride;
  };
  registeredAt: Date;
  lastTestAt?: Date;
  updatedAt: Date;
}

