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
  IdentityLifecycleConfigurationEntity,
  APIGatewayConfigurationEntity,
  DistributedSystemsConfigurationEntity,
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

class IdentityLifecycleTestLogicDto {
  @IsOptional()
  @IsBoolean()
  validateWorkflow?: boolean;

  @IsOptional()
  @IsBoolean()
  checkMFA?: boolean;

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

export class CreateIdentityLifecycleConfigurationDto extends BaseConfigurationDto {
  @IsNotEmpty()
  @IsEnum(['identity-lifecycle'])
  type: 'identity-lifecycle';

  @IsOptional()
  @IsObject()
  onboardingWorkflow?: {
    steps: Array<{
      name: string;
      required: boolean;
      description?: string;
    }>;
  };

  @IsOptional()
  @IsObject()
  pamConfig?: {
    maxJITDuration?: number;
    requireApproval?: boolean;
    emergencyAccessEnabled?: boolean;
  };

  @IsOptional()
  @IsObject()
  credentialRotationRules?: {
    passwordMaxAge?: number;
    apiKeyMaxAge?: number;
    requireMFA?: boolean;
  };

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => IdentityLifecycleTestLogicDto)
  testLogic?: IdentityLifecycleTestLogicDto;
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

export type CreateTestConfigurationDto =
  | CreateRLSCLSConfigurationDto
  | CreateNetworkPolicyConfigurationDto
  | CreateDLPConfigurationDto
  | CreateIdentityLifecycleConfigurationDto
  | CreateAPIGatewayConfigurationDto
  | CreateDistributedSystemsConfigurationDto;

