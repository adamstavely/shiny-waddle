import { IsNotEmpty, IsString, IsObject, IsArray, ValidateNested, IsOptional, IsIn, IsNumber, ArrayMinSize } from 'class-validator';
import { Type } from 'class-transformer';
import { DatabaseConfig, TestQuery, User, DynamicMaskingRule } from '../../../../core/types';

class DatabaseConfigDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['postgresql', 'mysql', 'mssql', 'oracle', 'sqlite'])
  type: 'postgresql' | 'mysql' | 'mssql' | 'oracle' | 'sqlite';

  @IsOptional()
  @IsString()
  connectionString?: string;

  @IsOptional()
  @IsString()
  host?: string;

  @IsOptional()
  @IsNumber()
  port?: number;

  @IsOptional()
  @IsString()
  database?: string;

  @IsOptional()
  @IsString()
  username?: string;

  @IsOptional()
  @IsString()
  password?: string;
}

export class TestRLSCoverageDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => DatabaseConfigDto)
  database: DatabaseConfigDto;
}

export class TestCLSCoverageDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => DatabaseConfigDto)
  database: DatabaseConfigDto;
}

export class TestDynamicMaskingDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  query: TestQuery;

  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  user: User;

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Array)
  maskingRules: DynamicMaskingRule[];
}

class TestQueryDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  sql?: string;

  @IsOptional()
  @IsString()
  apiEndpoint?: string;

  @IsOptional()
  @IsString()
  method?: string;

  @IsOptional()
  expectedResult?: any[];
}

export class TestCrossTenantIsolationDto {
  @IsNotEmpty()
  @IsString()
  tenant1: string;

  @IsNotEmpty()
  @IsString()
  tenant2: string;

  @IsNotEmpty()
  @IsArray()
  @ArrayMinSize(1, { message: 'At least one test query is required' })
  @ValidateNested({ each: true })
  @Type(() => TestQueryDto)
  testQueries: TestQueryDto[];
}

