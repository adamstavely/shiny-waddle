import { IsString, IsOptional, IsEnum, IsObject, IsUrl, IsBoolean, ValidateNested, IsArray } from 'class-validator';
import { Type } from 'class-transformer';
import { ApplicationInfrastructure } from '../entities/application.entity';

export enum ApplicationType {
  API = 'api',
  WEB = 'web',
  MICROSERVICE = 'microservice',
  PIPELINE = 'pipeline',
  DATABASE = 'database',
  SALESFORCE_ORG = 'salesforce_org',
  ELASTIC_CLUSTER = 'elastic_cluster',
  KUBERNETES_CLUSTER = 'kubernetes_cluster',
}

export enum ApplicationStatus {
  ACTIVE = 'active',
  INACTIVE = 'inactive',
  MAINTENANCE = 'maintenance',
}

export class CreateApplicationDto {
  @IsString()
  name: string;

  @IsString()
  id: string;

  @IsEnum(ApplicationType)
  type: ApplicationType;

  @IsEnum(ApplicationStatus)
  @IsOptional()
  status?: ApplicationStatus;

  @IsUrl()
  @IsOptional()
  baseUrl?: string;

  @IsString()
  @IsOptional()
  team?: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsObject()
  @IsOptional()
  config?: Record<string, any>;

  // NEW: Infrastructure configuration
  @ValidateNested()
  @Type(() => Object)
  @IsOptional()
  infrastructure?: ApplicationInfrastructure;
}

