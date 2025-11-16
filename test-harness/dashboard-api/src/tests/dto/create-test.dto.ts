import {
  IsNotEmpty,
  IsString,
  IsEnum,
  IsOptional,
  IsArray,
  IsBoolean,
  IsObject,
  ValidateNested,
  IsNumber,
  IsDateString,
} from 'class-validator';
import { Type } from 'class-transformer';
import { TestType } from '../../../../core/types';

export class CreateAccessControlTestDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty()
  @IsEnum(['access-control'])
  testType: 'access-control';

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  policyIds: string[];

  @IsNotEmpty()
  @IsString()
  role: string;

  @IsNotEmpty()
  @IsObject()
  resource: any; // Resource object

  @IsOptional()
  @IsObject()
  context?: any; // Context object

  @IsNotEmpty()
  @IsBoolean()
  expectedDecision: boolean;

  @IsOptional()
  @IsString()
  policyRuleId?: string;
}

export class CreateDataBehaviorTestDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty()
  @IsEnum(['data-behavior'])
  testType: 'data-behavior';

  @IsNotEmpty()
  @IsObject()
  testQuery: any;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  allowedFields?: string[];

  @IsOptional()
  @IsArray()
  requiredFilters?: any[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  disallowedJoins?: string[];

  @IsOptional()
  @IsObject()
  expectedResult?: any;
}

export class CreateDLPTestDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty()
  @IsEnum(['dlp'])
  testType: 'dlp';

  // Pattern-based test
  @IsOptional()
  @IsObject()
  pattern?: any;

  @IsOptional()
  @IsObject()
  testData?: any;

  @IsOptional()
  @IsBoolean()
  expectedDetection?: boolean;

  // OR Bulk export test
  @IsOptional()
  @IsEnum(['csv', 'json', 'excel', 'api'])
  bulkExportType?: 'csv' | 'json' | 'excel' | 'api';

  @IsOptional()
  @IsNumber()
  bulkExportLimit?: number;

  @IsOptional()
  @IsNumber()
  testRecordCount?: number;

  @IsOptional()
  @IsBoolean()
  expectedBlocked?: boolean;

  // OR PII detection rule test
  @IsOptional()
  @IsObject()
  piiDetectionRule?: any;

  // OR Custom check test
  @IsOptional()
  @IsObject()
  customCheck?: any;
}

export class CreateAPISecurityTestDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty()
  @IsEnum(['api-security'])
  testType: 'api-security';

  // One of these should be provided
  @IsOptional()
  @IsObject()
  apiVersion?: any;

  @IsOptional()
  @IsObject()
  gatewayPolicy?: any;

  @IsOptional()
  @IsObject()
  webhook?: any;

  @IsOptional()
  @IsObject()
  graphql?: any;

  @IsOptional()
  @IsObject()
  apiContract?: any;

  @IsOptional()
  @IsObject()
  expectedResult?: any;
}

// Base DTO class for all test types - includes all possible fields as optional
// Validation should be done at the service level based on testType
export class CreateTestDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsNotEmpty()
  @IsEnum([
    'access-control',
    'data-behavior',
    'contract',
    'dataset-health',
    'rls-cls',
    'network-policy',
    'dlp',
    'api-gateway',
    'distributed-systems',
    'api-security',
    'data-pipeline',
  ])
  testType: TestType;

  @IsOptional()
  @IsString()
  createdBy?: string;

  // AccessControlTest fields
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  policyIds?: string[];

  @IsOptional()
  @IsString()
  role?: string;

  @IsOptional()
  @IsObject()
  resource?: any;

  @IsOptional()
  @IsObject()
  context?: any;

  @IsOptional()
  @IsBoolean()
  expectedDecision?: boolean;

  @IsOptional()
  @IsString()
  policyRuleId?: string;

  // DataBehaviorTest fields
  @IsOptional()
  @IsObject()
  testQuery?: any;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  allowedFields?: string[];

  @IsOptional()
  @IsArray()
  requiredFilters?: any[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  disallowedJoins?: string[];

  @IsOptional()
  @IsObject()
  expectedResult?: any;

  // ContractTest fields
  @IsOptional()
  @IsObject()
  contract?: any;

  @IsOptional()
  @IsBoolean()
  expectedCompliance?: boolean;

  // DatasetHealthTest fields
  @IsOptional()
  @IsObject()
  dataset?: any;

  @IsOptional()
  @IsArray()
  privacyThresholds?: any[];

  @IsOptional()
  @IsArray()
  statisticalFidelityTargets?: any[];

  // RLSCLSTest fields
  @IsOptional()
  @IsObject()
  database?: any;

  // NetworkPolicyTest fields
  @IsOptional()
  @IsString()
  source?: string;

  @IsOptional()
  @IsString()
  target?: string;

  @IsOptional()
  @IsEnum(['tcp', 'udp', 'icmp', 'all'])
  protocol?: 'tcp' | 'udp' | 'icmp' | 'all';

  @IsOptional()
  @IsNumber()
  port?: number;

  // DLPTest fields
  @IsOptional()
  @IsObject()
  pattern?: any;

  @IsOptional()
  testData?: any;

  @IsOptional()
  @IsBoolean()
  expectedDetection?: boolean;

  @IsOptional()
  @IsEnum(['csv', 'json', 'excel', 'api'])
  bulkExportType?: 'csv' | 'json' | 'excel' | 'api';

  @IsOptional()
  @IsNumber()
  bulkExportLimit?: number;

  @IsOptional()
  @IsNumber()
  testRecordCount?: number;

  @IsOptional()
  @IsBoolean()
  expectedBlocked?: boolean;

  @IsOptional()
  @IsObject()
  piiDetectionRule?: any;

  @IsOptional()
  @IsObject()
  customCheck?: any;

  // APIGatewayTest fields
  @IsOptional()
  @IsString()
  gatewayType?: string;

  @IsOptional()
  @IsString()
  endpoint?: string;

  @IsOptional()
  @IsString()
  method?: string;

  @IsOptional()
  @IsString()
  policyId?: string;

  @IsOptional()
  @IsString()
  policyType?: string;

  // DistributedSystemsTest fields
  @IsOptional()
  @IsObject()
  region?: any;

  // APISecurityTest fields
  @IsOptional()
  @IsObject()
  apiVersion?: any;

  @IsOptional()
  @IsObject()
  gatewayPolicy?: any;

  @IsOptional()
  @IsObject()
  webhook?: any;

  @IsOptional()
  @IsObject()
  graphql?: any;

  @IsOptional()
  @IsObject()
  apiContract?: any;

  // DataPipelineTest fields
  @IsOptional()
  @IsString()
  pipelineType?: string;

  @IsOptional()
  @IsObject()
  dataSource?: any;

  @IsOptional()
  @IsObject()
  dataDestination?: any;
}

