import { IsString, IsOptional, IsObject, IsBoolean, IsArray } from 'class-validator';

export enum ValidatorStatus {
  ENABLED = 'enabled',
  DISABLED = 'disabled',
}

export class CreateValidatorDto {
  @IsString()
  id: string;

  @IsString()
  name: string;

  @IsString()
  description: string;

  @IsString()
  testType: string;

  @IsString()
  version: string;

  @IsOptional()
  @IsObject()
  metadata?: {
    supportedTestTypes?: string[];
    requiredConfig?: string[];
    optionalConfig?: string[];
    dependencies?: string[];
    tags?: string[];
    exampleConfig?: any;
  };

  @IsOptional()
  @IsObject()
  config?: Record<string, any>;

  @IsOptional()
  @IsBoolean()
  enabled?: boolean;
}

