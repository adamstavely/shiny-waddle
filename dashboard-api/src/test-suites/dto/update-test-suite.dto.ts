import {
  IsOptional,
  IsString,
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

export class UpdateTestSuiteDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  applicationId?: string;

  @IsOptional()
  @IsString()
  team?: string;

  @IsOptional()
  @IsString()
  @IsIn(VALID_TEST_TYPES)
  testType?: string;

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

