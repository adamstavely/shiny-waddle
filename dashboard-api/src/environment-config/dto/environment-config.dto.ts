import {
  IsNotEmpty,
  IsString,
  IsObject,
  IsArray,
  ValidateNested,
  IsOptional,
  IsIn,
  IsNumber,
} from 'class-validator';
import { Type } from 'class-transformer';
import { ABACPolicy } from '../../../../heimdall-framework/core/types';

export class ValidateEnvironmentDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['dev', 'staging', 'prod'])
  environment: 'dev' | 'staging' | 'prod';

  @IsOptional()
  @IsObject()
  variables?: Record<string, string>;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  configFiles?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  secrets?: string[];
}

export class SecretsManagerConnectionDto {
  @IsOptional()
  @IsString()
  address?: string;

  @IsOptional()
  @IsString()
  token?: string;

  @IsOptional()
  @IsString()
  vaultUrl?: string;

  @IsOptional()
  @IsString()
  projectId?: string;

  @IsOptional()
  @IsObject()
  iamPolicy?: any;

  @IsOptional()
  @IsObject()
  rotationConfig?: {
    enabled: boolean;
    interval?: number;
  };

  @IsOptional()
  @IsObject()
  logging?: {
    enabled: boolean;
    level?: 'none' | 'basic' | 'detailed';
  };

  @IsOptional()
  @IsString()
  injectionMethod?: string;

  @IsOptional()
  @IsString()
  injectionTime?: string;
}

export class ValidateSecretsDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['vault', 'aws-secrets-manager', 'azure-key-vault', 'gcp-secret-manager', 'kubernetes', 'env-var'])
  type: 'vault' | 'aws-secrets-manager' | 'azure-key-vault' | 'gcp-secret-manager' | 'kubernetes' | 'env-var';

  @IsOptional()
  @IsObject()
  @ValidateNested()
  @Type(() => SecretsManagerConnectionDto)
  connection?: SecretsManagerConnectionDto;
}

export class DetectDriftDto {
  @IsNotEmpty()
  @IsString()
  baselineEnvironment: string;

  @IsNotEmpty()
  @IsString()
  currentEnvironment: string;

  @IsOptional()
  @IsObject()
  variables?: Record<string, string>;

  @IsOptional()
  @IsObject()
  currentVariables?: Record<string, string>;

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  configFiles?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  currentConfigFiles?: string[];
}

export class IsolationRuleDto {
  @IsNotEmpty()
  @IsString()
  fromEnvironment: string;

  @IsNotEmpty()
  @IsString()
  toEnvironment: string;

  @IsNotEmpty()
  allowed: boolean;

  @IsOptional()
  @IsArray()
  conditions?: Array<{
    attribute: string;
    operator: string;
    value: any;
  }>;
}

export class PromotionRuleDto {
  @IsNotEmpty()
  @IsString()
  fromEnvironment: string;

  @IsNotEmpty()
  @IsString()
  toEnvironment: string;

  @IsNotEmpty()
  @IsNumber()
  requiredApprovals: number;

  @IsNotEmpty()
  @IsArray()
  @IsString({ each: true })
  requiredChecks: string[];

  @IsOptional()
  @IsArray()
  conditions?: Array<{
    attribute: string;
    operator: string;
    value: any;
  }>;
}

export class ValidateEnvironmentPoliciesDto {
  @IsNotEmpty()
  @IsString()
  @IsIn(['dev', 'staging', 'prod'])
  environment: 'dev' | 'staging' | 'prod';

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => Object)
  policies?: ABACPolicy[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => IsolationRuleDto)
  isolationRules?: IsolationRuleDto[];

  @IsOptional()
  @IsArray()
  @ValidateNested({ each: true })
  @Type(() => PromotionRuleDto)
  promotionRules?: PromotionRuleDto[];
}

