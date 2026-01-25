import {
  IsNotEmpty,
  IsString,
  IsOptional,
  IsArray,
  IsNumber,
  IsBoolean,
  IsEnum,
  Min,
  Max,
  IsIn,
} from 'class-validator';
import { TestSuiteStatus } from '../entities/test-suite.entity';
import { TestDomain } from '../../../../core/types';

// Valid test types
const VALID_TEST_TYPES = [
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
] as const;

export class CreateTestSuiteDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  applicationId: string;

  @IsNotEmpty()
  @IsString()
  team: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(VALID_TEST_TYPES)
  testType: string;

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
  description?: string;

  @IsOptional()
  @IsEnum(['passing', 'failing', 'pending', 'error'])
  status?: TestSuiteStatus;

  @IsOptional()
  @IsNumber()
  @Min(0)
  testCount?: number;

  @IsOptional()
  @IsNumber()
  @Min(0)
  @Max(100)
  score?: number;


  @IsOptional()
  @IsBoolean()
  enabled?: boolean;
}

