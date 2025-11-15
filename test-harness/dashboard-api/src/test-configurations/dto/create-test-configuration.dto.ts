import {
  IsNotEmpty,
  IsString,
  IsOptional,
  IsArray,
  IsObject,
  IsNumber,
  IsBoolean,
  ValidateNested,
  IsEnum,
  ArrayMinSize,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  TestConfigurationType,
  RLSCLSConfigurationEntity,
  NetworkPolicyConfigurationEntity,
  DLPConfigurationEntity,
  APIGatewayConfigurationEntity,
  DistributedSystemsConfigurationEntity,
  APISecurityConfigurationEntity,
  DataPipelineConfigurationEntity,
  RegionConfig,
} from '../entities/test-configuration.entity';
import { DatabaseConfigDto } from '../../rls-cls/dto/rls-cls.dto';
import { TestQueryDto } from '../../rls-cls/dto/rls-cls.dto';

class BaseConfigurationDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  tags?: string[];

  @IsOptional()
  @IsBoolean()
  enabled?: boolean;
}

class RLSCLSValidationRulesDto {
  @IsOptional()
  @IsNumber()
  minRLSCoverage?: number;

  @IsOptional()
  @IsNumber()
  minCLSCoverage?: number;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  requiredPolicies?: string[];
}

class RLSCLSTestLogicDto {
  @IsOptional()
  @IsBoolean()
  skipDisabledPolicies?: boolean;

  @IsOptional()
  @IsBoolean()
  validateCrossTenant?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customValidations?: Array<{
    name: string;
    condition: string;
    description?: string;
  }>;
}

export class CreateRLSCLSConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['rls-cls'])
  type: 'rls-cls';

  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => DatabaseConfigDto)
  database: DatabaseConfigDto;

  @IsNotEmpty()
  @IsArray()
  @ArrayMinSize(0)
  @ValidateNested({ each: true })
  @Type(() => TestQueryDto)
  testQueries: TestQueryDto[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => RLSCLSValidationRulesDto)
  validationRules?: RLSCLSValidationRulesDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => RLSCLSTestLogicDto)
  testLogic?: RLSCLSTestLogicDto;
}

class FirewallRuleDto {
  @IsNotEmpty()
  @IsString()
  id: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  source: string;

  @IsNotEmpty()
  @IsString()
  destination: string;

  @IsNotEmpty()
  @IsString()
  protocol: 'tcp' | 'udp' | 'icmp' | 'all';

  @IsOptional()
  @IsNumber()
  port?: number;

  @IsNotEmpty()
  @IsString()
  action: 'allow' | 'deny';

  @IsNotEmpty()
  @IsBoolean()
  enabled: boolean;
}

class NetworkSegmentDto {
  @IsNotEmpty()
  @IsString()
  id: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  cidr?: string;

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  services: string[];

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  allowedConnections: string[];

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  deniedConnections: string[];
}

class NetworkPolicyTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateConnectivity?: boolean;

  @IsOptional()
  @IsBoolean()
  checkSegmentation?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customRules?: Array<{
    source: string;
    target: string;
    expected: boolean;
    description?: string;
  }>;
}

export class CreateNetworkPolicyConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['network-policy'])
  type: 'network-policy';

  @IsNotEmpty()
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => FirewallRuleDto)
  firewallRules: FirewallRuleDto[];

  @IsNotEmpty()
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => NetworkSegmentDto)
  networkSegments: NetworkSegmentDto[];

  @IsOptional()
  @IsObject()
  serviceMeshConfig?: any;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => NetworkPolicyTestLogicDto)
  testLogic?: NetworkPolicyTestLogicDto;
}

class DLPPatternDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  type: 'regex' | 'keyword' | 'data-classification' | 'custom';

  @IsNotEmpty()
  @IsString()
  pattern: string;

  @IsNotEmpty()
  @IsString()
  severity: 'critical' | 'high' | 'medium' | 'low';
}

class DLPTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateAPIResponses?: boolean;

  @IsOptional()
  @IsBoolean()
  checkBulkExports?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customChecks?: Array<{
    name: string;
    condition: string;
    description?: string;
  }>;
}

export class CreateDLPConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['dlp'])
  type: 'dlp';

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => DLPPatternDto)
  patterns?: DLPPatternDto[];

  @IsOptional()
  @IsObject()
  bulkExportLimits?: {
    csv?: number;
    json?: number;
    excel?: number;
    api?: number;
  };

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  piiDetectionRules?: Array<{
    fieldName: string;
    pattern: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => DLPTestLogicDto)
  testLogic?: DLPTestLogicDto;
}

class APIGatewayTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateRateLimiting?: boolean;

  @IsOptional()
  @IsBoolean()
  checkServiceAuth?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customValidations?: Array<{
    name: string;
    condition: string;
    description?: string;
  }>;
}

export class CreateAPIGatewayConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['api-gateway'])
  type: 'api-gateway';

  @IsOptional()
  @IsObject()
  rateLimitConfig?: {
    defaultLimit?: number;
    defaultTimeWindow?: number;
    perEndpointLimits?: Record<string, { limit: number; window: number }>;
  };

  @IsOptional()
  @IsObject()
  serviceAuthConfig?: {
    methods: Array<'mtls' | 'jwt' | 'api-key' | 'oauth2'>;
    requiredForEndpoints?: string[];
  };

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  gatewayPolicies?: Array<{
    id: string;
    name: string;
    endpoint: string;
    method: string;
    rules: any[];
  }>;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => APIGatewayTestLogicDto)
  testLogic?: APIGatewayTestLogicDto;
}

class RegionConfigDto {
  @IsNotEmpty()
  @IsString()
  id: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  endpoint: string;

  @IsOptional()
  @IsString()
  pdpEndpoint?: string;

  @IsOptional()
  @IsString()
  timezone?: string;

  @IsOptional()
  @IsNumber()
  latency?: number;

  @IsOptional()
  @IsObject()
  credentials?: Record<string, string>;
}

class PolicySyncDto {
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @IsOptional()
  @IsNumber()
  syncInterval?: number;

  @IsOptional()
  @IsEnum(['strong', 'eventual', 'weak'])
  consistencyLevel?: 'strong' | 'eventual' | 'weak';
}

class CoordinationDto {
  @IsOptional()
  @IsEnum(['consul', 'etcd', 'zookeeper', 'custom'])
  type?: 'consul' | 'etcd' | 'zookeeper' | 'custom';

  @IsOptional()
  @IsString()
  endpoint?: string;
}

class DistributedSystemsTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateConsistency?: boolean;

  @IsOptional()
  @IsBoolean()
  checkSynchronization?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customValidations?: Array<{
    name: string;
    condition: string;
    description?: string;
  }>;
}

export class CreateDistributedSystemsConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['distributed-systems'])
  type: 'distributed-systems';

  @IsNotEmpty()
  @IsArray()
  @ArrayMinSize(1)
  @ValidateNested({ each: true })
  @Type(() => RegionConfigDto)
  regions: RegionConfigDto[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => PolicySyncDto)
  policySync?: PolicySyncDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => CoordinationDto)
  coordination?: CoordinationDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => DistributedSystemsTestLogicDto)
  testLogic?: DistributedSystemsTestLogicDto;
}

class APISecurityEndpointDto {
  @IsOptional()
  @IsString()
  id?: string;

  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  endpoint: string;

  @IsNotEmpty()
  @IsEnum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'OPTIONS';

  @IsNotEmpty()
  @IsEnum(['rest', 'graphql', 'authentication', 'authorization', 'rate-limiting', 'vulnerability'])
  apiType: 'rest' | 'graphql' | 'authentication' | 'authorization' | 'rate-limiting' | 'vulnerability';

  @IsOptional()
  @IsNumber()
  expectedStatus?: number;

  @IsOptional()
  @IsBoolean()
  expectedAuthRequired?: boolean;

  @IsOptional()
  @IsBoolean()
  expectedRateLimit?: boolean;

  @IsOptional()
  @IsObject()
  body?: any;

  @IsOptional()
  @IsObject()
  headers?: Record<string, string>;
}

class APISecurityTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateAuthentication?: boolean;

  @IsOptional()
  @IsBoolean()
  validateAuthorization?: boolean;

  @IsOptional()
  @IsBoolean()
  checkRateLimiting?: boolean;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  selectedTestSuites?: string[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customValidations?: Array<{
    name: string;
    condition: string;
    description?: string;
  }>;
}

export class CreateAPISecurityConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['api-security'])
  type: 'api-security';

  @IsNotEmpty()
  @IsString()
  baseUrl: string;

  @IsOptional()
  @IsObject()
  authentication?: {
    type: 'bearer' | 'basic' | 'oauth2' | 'api-key' | 'jwt';
    credentials: Record<string, string>;
  };

  @IsOptional()
  @IsObject()
  rateLimitConfig?: {
    maxRequests?: number;
    windowSeconds?: number;
    strategy?: 'fixed' | 'sliding' | 'token-bucket';
  };

  @IsOptional()
  @IsObject()
  headers?: Record<string, string>;

  @IsOptional()
  @IsNumber()
  timeout?: number;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => APISecurityEndpointDto)
  endpoints?: APISecurityEndpointDto[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => APISecurityTestLogicDto)
  testLogic?: APISecurityTestLogicDto;
}

class DataPipelineConnectionDto {
  @IsOptional()
  @IsEnum(['kafka', 'spark', 'airflow', 'dbt', 'custom'])
  type?: 'kafka' | 'spark' | 'airflow' | 'dbt' | 'custom';

  @IsOptional()
  @IsString()
  endpoint?: string;

  @IsOptional()
  @IsObject()
  credentials?: Record<string, string>;
}

class DataPipelineDataSourceDto {
  @IsOptional()
  @IsEnum(['database', 'api', 'file', 'stream'])
  type?: 'database' | 'api' | 'file' | 'stream';

  @IsOptional()
  @IsString()
  connectionString?: string;
}

class DataPipelineDataDestinationDto {
  @IsOptional()
  @IsEnum(['database', 'data-warehouse', 'data-lake', 'api'])
  type?: 'database' | 'data-warehouse' | 'data-lake' | 'api';

  @IsOptional()
  @IsString()
  connectionString?: string;
}

class DataPipelineTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateAccessControl?: boolean;

  @IsOptional()
  @IsBoolean()
  checkDataQuality?: boolean;

  @IsOptional()
  @IsBoolean()
  validateTransformations?: boolean;

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  customValidations?: Array<{
    name: string;
    condition: string;
    description?: string;
  }>;
}

export class CreateDataPipelineConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['data-pipeline'])
  type: 'data-pipeline';

  @IsNotEmpty()
  @IsEnum(['etl', 'streaming', 'batch', 'real-time'])
  pipelineType: 'etl' | 'streaming' | 'batch' | 'real-time';

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => DataPipelineConnectionDto)
  connection?: DataPipelineConnectionDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => DataPipelineDataSourceDto)
  dataSource?: DataPipelineDataSourceDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => DataPipelineDataDestinationDto)
  dataDestination?: DataPipelineDataDestinationDto;

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => DataPipelineTestLogicDto)
  testLogic?: DataPipelineTestLogicDto;
}

export type CreateTestConfigurationDto =
  | CreateRLSCLSConfigurationDto
  | CreateNetworkPolicyConfigurationDto
  | CreateDLPConfigurationDto
  | CreateAPIGatewayConfigurationDto
  | CreateDistributedSystemsConfigurationDto
  | CreateAPISecurityConfigurationDto
  | CreateDataPipelineConfigurationDto;

