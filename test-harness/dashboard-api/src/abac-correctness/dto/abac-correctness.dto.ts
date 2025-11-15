import {
  IsNotEmpty,
  IsString,
  IsObject,
  IsArray,
  ValidateNested,
  IsOptional,
  IsIn,
  IsNumber,
  IsBoolean,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ABACPolicy, PDPRequest } from '../../../../core/types';

export class ValidationRuleDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['required', 'format', 'range', 'enum', 'regex', 'custom'])
  type: 'required' | 'format' | 'range' | 'enum' | 'regex' | 'custom';

  @IsOptional()
  value?: any;

  @IsOptional()
  @IsString()
  message?: string;
}

export class FreshnessConfigDto {
  @IsNotEmpty()
  @IsNumber()
  maxAge: number;

  @IsNotEmpty()
  @IsString()
  @IsIn(['seconds', 'minutes', 'hours'])
  unit: 'seconds' | 'minutes' | 'hours';
}

export class ABACAttributeDto {
  @IsNotEmpty()
  @IsString()
  name: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(['string', 'number', 'boolean', 'array', 'object'])
  type: 'string' | 'number' | 'boolean' | 'array' | 'object';

  @IsNotEmpty()
  @IsString()
  @IsIn(['ldap', 'database', 'api', 'jwt', 'custom'])
  source: 'ldap' | 'database' | 'api' | 'jwt' | 'custom';

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ValidationRuleDto)
  validation: ValidationRuleDto[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => FreshnessConfigDto)
  freshness?: FreshnessConfigDto;
}

export class ValidateAttributesDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ABACAttributeDto)
  attributes: ABACAttributeDto[];

  @IsOptional()
  @IsObject()
  testValue?: any;
}

export class CompletenessTestConfigDto {
  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  resourceTypes: string[];

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  userRoles: string[];

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  actions: string[];

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  policies: ABACPolicy[];
}

export class PerformanceTestLoadConfigDto {
  @IsOptional()
  @IsNumber()
  concurrentRequests?: number;

  @IsOptional()
  @IsNumber()
  duration?: number;
}

export class PerformanceTestConfigDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  policies: ABACPolicy[];

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  testRequests: PDPRequest[];

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => PerformanceTestLoadConfigDto)
  loadConfig?: PerformanceTestLoadConfigDto;
}

export class ConflictTestConfigDto {
  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  policies: ABACPolicy[];

  @IsNotEmpty()
  @IsString()
  @IsIn(['priority', 'deny-override', 'allow-override', 'first-match'])
  resolutionStrategy: 'priority' | 'deny-override' | 'allow-override' | 'first-match';
}

export class TransformationRuleDto {
  @IsNotEmpty()
  @IsString()
  sourceAttribute: string;

  @IsNotEmpty()
  @IsString()
  targetAttribute: string;

  @IsNotEmpty()
  @IsString()
  @IsIn(['copy', 'map', 'derive', 'aggregate'])
  transformation: 'copy' | 'map' | 'derive' | 'aggregate';

  @IsOptional()
  @IsString()
  function?: string;
}

export class PropagationTestConfigDto {
  @IsNotEmpty()
  @IsString()
  sourceSystem: string;

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  targetSystems: string[];

  @IsNotEmpty()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => ABACAttributeDto)
  attributes: ABACAttributeDto[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => TransformationRuleDto)
  transformationRules?: TransformationRuleDto[];
}

