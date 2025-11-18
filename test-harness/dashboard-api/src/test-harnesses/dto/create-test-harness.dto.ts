import {
  IsNotEmpty,
  IsString,
  IsOptional,
  IsArray,
  IsIn,
  IsEnum,
} from 'class-validator';
import { TestDomain } from '../../../../core/types';

// Valid test types (kept for backward compatibility)
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

export class CreateTestHarnessDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  @IsNotEmpty()
  @IsEnum([
    'api_security',
    'platform_config',
    'identity',
    'data_contracts',
    'salesforce',
    'elastic',
    'idp_platform',
  ])
  domain: TestDomain; // Required: all suites in harness must have this domain

  @IsOptional()
  @IsString()
  @IsIn(VALID_TEST_TYPES)
  testType?: string; // Deprecated: kept for backward compatibility during migration

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  testSuiteIds?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  applicationIds?: string[];

  @IsOptional()
  @IsString()
  team?: string;
}

