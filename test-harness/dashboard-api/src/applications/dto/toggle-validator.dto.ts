import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class ToggleValidatorDto {
  @IsBoolean()
  enabled: boolean;

  @IsString()
  @IsOptional()
  reason?: string;
}

