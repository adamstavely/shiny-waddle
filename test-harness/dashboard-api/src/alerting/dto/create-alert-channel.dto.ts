import { IsString, IsBoolean, IsEnum, IsObject, IsOptional } from 'class-validator';

export class CreateAlertChannelDto {
  @IsString()
  name: string;

  @IsEnum(['email', 'slack', 'pagerduty', 'webhook', 'teams', 'custom'])
  type: 'email' | 'slack' | 'pagerduty' | 'webhook' | 'teams' | 'custom';

  @IsBoolean()
  enabled: boolean;

  @IsObject()
  config: Record<string, any>; // Channel-specific configuration

  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
