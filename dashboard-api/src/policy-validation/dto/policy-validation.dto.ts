import { IsNotEmpty, IsArray, IsObject, IsOptional, IsNumber, ValidateNested } from 'class-validator';
import { Type } from 'class-transformer';
import { ABACPolicy, Resource } from '../../../../heimdall-framework/core/types';
import { PolicyTestCase } from '../../../../heimdall-framework/services/policy-as-code';

export class DetectConflictsDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  policies: ABACPolicy[];
}

export class AnalyzeCoverageDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  resources: Resource[];

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  policies: ABACPolicy[];
}

export class TestPerformanceDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  policy: ABACPolicy;

  @IsOptional()
  @IsNumber()
  iterations?: number;
}

export class RunRegressionDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  baselinePolicies: ABACPolicy[];

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  currentPolicies: ABACPolicy[];

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  testCases: PolicyTestCase[];
}

export class SimulatePolicyDto {
  @IsNotEmpty()
  @IsObject()
  @ValidateNested()
  @Type(() => Object)
  policy: ABACPolicy;

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  testCases: PolicyTestCase[];
}

