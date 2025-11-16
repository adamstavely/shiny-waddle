import {
  IsOptional,
  IsString,
  IsArray,
  IsIn,
} from 'class-validator';

// Valid test types
const VALID_TEST_TYPES = [
  'access-control',
  'data-behavior',
  'dataset-health',
  'rls-cls',
  'network-policy',
  'dlp',
  'api-gateway',
  'distributed-systems',
  'api-security',
  'data-pipeline',
] as const;

export class UpdateTestHarnessDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  @IsIn(VALID_TEST_TYPES)
  testType?: string;

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

