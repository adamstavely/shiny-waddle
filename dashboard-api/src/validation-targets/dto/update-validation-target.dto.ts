import { IsString, IsOptional, IsObject, IsArray } from 'class-validator';

export class UpdateValidationTargetDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsObject()
  connectionConfig?: Record<string, any>;

  @IsOptional()
  @IsArray()
  ruleIds?: string[];
}

