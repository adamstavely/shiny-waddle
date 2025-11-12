import { IsNotEmpty, IsString, IsObject, IsArray, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { DatabaseConfig, TestQuery, User, DynamicMaskingRule } from '../../../../core/types';

export class TestRLSCoverageDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  database: DatabaseConfig;
}

export class TestCLSCoverageDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  database: DatabaseConfig;
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

export class TestCrossTenantIsolationDto {
  @IsNotEmpty()
  @IsString()
  tenant1: string;

  @IsNotEmpty()
  @IsString()
  tenant2: string;

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Array)
  testQueries: TestQuery[];
}

