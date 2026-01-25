import { IsString, IsOptional, IsObject, IsArray } from 'class-validator';

export class UpdateValidationTargetDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  environment?: string;

  @IsOptional()
  @IsObject()
  connectionConfig?: Record<string, any>;

  @IsOptional()
  @IsString()
  baselineId?: string;

  @IsOptional()
  @IsArray()
  ruleIds?: string[];
}

