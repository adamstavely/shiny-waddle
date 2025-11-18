import { IsString, IsEnum, IsOptional, IsNotEmpty, IsBoolean, IsArray } from 'class-validator';

export class CreateAllowlistDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsEnum(['ip', 'user', 'resource', 'pattern'])
  type: 'ip' | 'user' | 'resource' | 'pattern';

  @IsArray()
  @IsString({ each: true })
  @IsNotEmpty()
  values: string[];

  @IsArray()
  @IsString({ each: true })
  @IsOptional()
  policyIds?: string[];

  @IsBoolean()
  @IsOptional()
  enabled?: boolean;
}

