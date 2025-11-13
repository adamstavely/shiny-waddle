import {
  IsOptional,
  IsString,
  IsArray,
  IsNumber,
  IsBoolean,
  IsEnum,
  Min,
  Max,
} from 'class-validator';
import { TestSuiteStatus } from '../entities/test-suite.entity';

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
  testTypes?: string[];

  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  testConfigurationIds?: string[];
}

