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
  @IsArray()
  @IsString({ each: true })
  testTypes?: string[]; // Deprecated: kept for backward compatibility

  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  testConfigurationIds?: string[];
}

