import { IsBoolean, IsOptional, IsString } from 'class-validator';

export class ToggleTestConfigDto {
  @IsBoolean()
  enabled: boolean;

  @IsString()
  @IsOptional()
  reason?: string;
}

