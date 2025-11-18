import { IsString, IsEnum, IsOptional, IsNotEmpty, IsDateString } from 'class-validator';

export class CreateExceptionDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsString()
  @IsOptional()
  policyId?: string;

  @IsString()
  @IsOptional()
  ruleId?: string;

  @IsString()
  @IsNotEmpty()
  reason: string;

  @IsString()
  @IsNotEmpty()
  requestedBy: string;

  @IsDateString()
  @IsOptional()
  expirationDate?: string;

  @IsString()
  @IsOptional()
  notes?: string;
}

