import { IsString, IsOptional, IsObject, IsBoolean } from 'class-validator';

export class UpdateValidatorDto {
  @IsOptional()
  @IsString()
  name?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsObject()
  config?: Record<string, any>;

  @IsOptional()
  @IsBoolean()
  enabled?: boolean;
}

