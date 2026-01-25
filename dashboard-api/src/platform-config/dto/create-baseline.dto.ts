import { IsString, IsOptional, IsNotEmpty, IsObject } from 'class-validator';

export class CreateBaselineDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsNotEmpty()
  environment: string;

  @IsObject()
  @IsNotEmpty()
  config: Record<string, any>;

  @IsString()
  @IsOptional()
  createdBy?: string;
}

