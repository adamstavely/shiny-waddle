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
import { TestType, TestDomain } from '../../../../core/types';

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
  @IsString()
  policyId: string; // 1:1 relationship with Policy

  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  inputs: {
    subject?: {
      role?: string;
      attributes?: Record<string, any>;
    };
    resource: any; // Resource object
    context?: any; // Context object
    action?: string;
  };

  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  expected: {
    allowed: boolean;
    reason?: string;
  };
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
    'dataset-health',
    'rls-cls',
    'network-policy',
    'dlp',
    'api-gateway',
    'distributed-systems',
    'api-security',
    'data-pipeline',
    'data-contract',
    'salesforce-config',
    'salesforce-security',
    'elastic-config',
    'elastic-security',
    'k8s-security',
    'k8s-workload',
    'idp-compliance',
  ])
  testType: TestType;

  @IsOptional()
  @IsEnum([
    'api_security',
    'platform_config',
    'identity',
    'data_contracts',
    'salesforce',
    'elastic',
    'idp_platform',
  ])
  domain?: TestDomain; // Optional: will be auto-populated from testType if not provided

  @IsOptional()
  @IsString()
  createdBy?: string;

  // AccessControlTest fields
  @IsOptional()
  @IsString()
  policyId?: string; // 1:1 relationship with Policy

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  inputs?: {
    subject?: {
      role?: string;
      attributes?: Record<string, any>;
    };
    resource?: any;
    context?: any;
    action?: string;
  };

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  expected?: {
    allowed?: boolean;
    reason?: string;
  };

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
  @IsString()
  applicationId?: string;

  @IsOptional()
  @IsString()
  databaseId?: string;

  @IsOptional()
  @IsObject()
  testQuery?: any;

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
  @IsEnum(['policy-consistency', 'multi-region', 'synchronization', 'transaction', 'eventual-consistency'])
  distributedTestType?: 'policy-consistency' | 'multi-region' | 'synchronization' | 'transaction' | 'eventual-consistency';

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

