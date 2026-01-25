import { IsString, IsOptional, IsObject, IsEnum, IsArray } from 'class-validator';

export enum ValidationTargetType {
  SALESFORCE = 'salesforce',
  ELASTIC_CLOUD = 'elastic-cloud',
  AWS = 'aws',
  AZURE = 'azure',
  OTHER = 'other',
}

export enum ValidationTargetStatus {
  HEALTHY = 'healthy',
  WARNINGS = 'warnings',
  ERRORS = 'errors',
  UNKNOWN = 'unknown',
}

export class CreateValidationTargetDto {
  @IsString()
  name: string;

  @IsEnum(ValidationTargetType)
  type: ValidationTargetType;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  environment?: string; // production, staging, development

  @IsObject()
  connectionConfig: Record<string, any>;

  @IsString()
  @IsOptional()
  baselineId?: string; // Reference to platform baseline

  @IsArray()
  @IsOptional()
  ruleIds?: string[];
}

