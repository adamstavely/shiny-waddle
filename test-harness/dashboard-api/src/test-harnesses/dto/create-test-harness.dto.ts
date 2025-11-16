import {
  IsNotEmpty,
  IsString,
  IsOptional,
  IsArray,
  IsIn,
} from 'class-validator';

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

export class CreateTestHarnessDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  description: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(VALID_TEST_TYPES)
  testType: string;

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

